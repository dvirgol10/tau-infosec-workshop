#include "fw_conntab.h"
#include "fw_log.h"

struct list_head conn_tab = LIST_HEAD_INIT(conn_tab); // the head of the connection table linked list
int num_conn_entries = 0;							  // holdes the total current number of connection entries

// clears the connection table - deletes each entry, freeing the memory, and zeros the connection entries counter
void free_conn_tab(void)
{
	conn_entry_node *conn_node, *tmp;
	list_for_each_entry_safe(conn_node, tmp, &conn_tab, list)
	{
		list_del(&conn_node->list);
		kfree(conn_node);
	}
	num_conn_entries = 0;
}

void remove_conn_node(conn_entry_node *conn_node)
{
	list_del(&conn_node->list);
	--num_conn_entries;
}

// gets a connection entry and adds it to the connection table (allocates a new node for it and adds it)
void add_conn_entry(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, state_t state, conn_entry_metadata_t metadata)
{
	conn_entry_node *conn_node = kmalloc(sizeof(conn_entry_node), GFP_KERNEL);
	conn_node->conn_entry.src_ip = src_ip;
	conn_node->conn_entry.src_port = src_port;
	conn_node->conn_entry.dst_ip = dst_ip;
	conn_node->conn_entry.dst_port = dst_port;
	conn_node->conn_entry.state = state;
	conn_node->conn_entry.metadata = metadata;
	list_add_tail(&conn_node->list, &conn_tab);
	++num_conn_entries;
}

int update_conn_tab_with_new_connection(struct sk_buff *skb, conn_entry_metadata_t metadata)
{
	conn_entry_node *conn_node;
	struct iphdr *hdr;
	__be32 src_ip, dst_ip;
	__be16 src_port, dst_port;
	hdr = ip_hdr(skb);
	src_ip = hdr->saddr;
	dst_ip = hdr->daddr;
	src_port = tcp_hdr(skb)->source;
	dst_port = tcp_hdr(skb)->dest;

	conn_node = find_matching_conn_entry_node(src_ip, src_port, dst_ip, dst_port);
	if (conn_node)
	{ // there is already a record for this connection
		if (conn_node->conn_entry.state == SYN_RECEIVED)
		{ // still trying to send SYN packet
			return 1;
		}
		else
		{
			return 0;
		}
	}

	add_conn_entry(src_ip, src_port, dst_ip, dst_port, SYN_RECEIVED, metadata);
	if (metadata.type != TCP_CONN_OTHER)
	{ // if we have a "special" TCP connection (HTTP or FTP or SMTP) we add a connection entry with our proxy as a source and the real server as the destination.
	  // at first the source port is invalid (0), in the future we will update it with proxy information which he writes to the module
		add_conn_entry(FAKE_CLIENT_ADDR_BE, 0, metadata.server_ip, metadata.server_port, WAITING_TO_START, metadata);
	}

	return 1;
}

conn_entry_node *find_matching_conn_entry_node(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port)
{
	conn_entry_node *conn_node;
	conn_entry_t conn_entry;

	// iterates over the connection table and searches for a match
	list_for_each_entry(conn_node, &conn_tab, list)
	{
		conn_entry = conn_node->conn_entry;
		if (((src_ip == conn_entry.src_ip) &&
			 (src_port == conn_entry.src_port) &&
			 (dst_ip == conn_entry.dst_ip) &&
			 (dst_port == conn_entry.dst_port)) || // we check both "sides" because we keep a single entry for an entire connection
			((src_ip == conn_entry.dst_ip) &&
			 (src_port == conn_entry.dst_port) &&
			 (dst_ip == conn_entry.src_ip) &&
			 (dst_port == conn_entry.src_port)))
		{ // if a match was found, return the node
			return conn_node;
		}
	}
	// if there is no compatible dynamic connection entry, we return NULL
	return NULL;
}

// update the tcp state of a connection entry
int update_conn_entry_state(conn_entry_node *conn_node, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __u16 pkt_syn, __u16 pkt_fin, __u16 pkt_rst)
{
	conn_entry_t *p_conn_entry = &conn_node->conn_entry;
	bool is_client = src_ip == p_conn_entry->src_ip;
	bool is_server = !is_client;

	if (pkt_rst)
	{
		remove_conn_node(conn_node); // remove the conn_node from the dynamic connection table because RESET connection has been sent
	}

	switch (p_conn_entry->state)
	{
	case WAITING_TO_START:
		if (is_client && pkt_syn)
		{
			// "WAITING_TO_START -> SYN_RECEIVED
			p_conn_entry->state = SYN_RECEIVED;
			return 1;
		}
		break;
	case SYN_RECEIVED:
		if (is_server && pkt_syn)
		{
			// "SYN_RECEIVED -> SYN_ACK_RECEIVED
			p_conn_entry->state = SYN_ACK_RECEIVED;
			return 1;
		}
		if (is_client && pkt_syn)
		{
			// "SYN_RECEIVED -> SYN_RECEIVED\n")
			return 1;
		}
		break;
	case SYN_ACK_RECEIVED:
		if (is_client)
		{
			p_conn_entry->state = ESTABLISHED;
			// "SYN_ACK_RECEIVED -> ESTABLISHED
			return 1;
		}
		break;
	case ESTABLISHED:
		if (!pkt_fin)
		{
			// "ESTABLISHED -> ESTABLISHED
			return 1;
		}
		else
		{
			// "ESTABLISHED -> FIN_1_RECEIVED
			p_conn_entry->state = FIN_1_RECEIVED;
			// Now the initiator of the FIN is treated as client and the other side as server
			p_conn_entry->src_ip = src_ip;
			p_conn_entry->src_port = src_port;
			p_conn_entry->dst_ip = dst_ip;
			p_conn_entry->dst_port = dst_port;
			return 1;
		}
		break;
	case FIN_1_RECEIVED:
		if (is_server && pkt_fin)
		{
			// "FIN_1_RECEIVED -> FIN_2_RECEIVED
			p_conn_entry->state = FIN_2_RECEIVED;
			return 1;
		}
		if (is_client && pkt_fin)
		{
			// "FIN_1_RECEIVED -> FIN_1_RECEIVED
			return 1;
		}
		break;
	case FIN_2_RECEIVED:
		if (is_client)
		{
			// "FIN_2_RECEIVED -> CLOSED
			remove_conn_node(conn_node); // remove the conn_node from the dynamic connection table because there is no more connection between the two endopints
			return 1;
		}
		break;
	}
	return 0;
}

// searches a matching connection table entry for the acked-TCP packet, writes it in the log and returns the verdict for the packet
verdict_t match_conn_entries(struct sk_buff *skb, int to_update_log)
{
	verdict_t verdict;
	conn_entry_node *conn_node;
	struct iphdr *hdr;
	__be32 src_ip, dst_ip;
	__be16 src_port, dst_port;
	// ip header part
	hdr = ip_hdr(skb);
	src_ip = hdr->saddr;
	dst_ip = hdr->daddr;

	src_port = tcp_hdr(skb)->source;
	dst_port = tcp_hdr(skb)->dest;

	conn_node = find_matching_conn_entry_node(src_ip, src_port, dst_ip, dst_port);
	if (conn_node == NULL) // if there is no matching connection entry we should drop the packet
	{
		verdict.action = NF_DROP;
		verdict.reason = REASON_NO_MATCHING_CONN_ENTRY;
	}
	else
	{ // if we found a matching connection entry, we try to update its state. If the packet doesn't match to the state we drop the packet
		if (update_conn_entry_state(conn_node, src_ip, src_port, dst_ip, dst_port, get_packet_syn(skb), get_packet_fin(skb), get_packet_rst(skb)))
		{
			verdict.action = NF_ACCEPT;
			verdict.reason = REASON_MATCHING_CONN_ENTRY;
		}
		else
		{
			verdict.action = NF_DROP;
			verdict.reason = REASON_NO_MATCHING_CONN_ENTRY;
		}
	}
	if (to_update_log)
	{
		update_log(skb, verdict.reason, verdict.action); // update the log with the input packet
	}
	return verdict;
}

__u16 get_packet_syn(struct sk_buff *skb)
{
	return tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_SYN;
}

__u16 get_packet_fin(struct sk_buff *skb)
{
	return tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_FIN;
}

__u16 get_packet_ack(struct sk_buff *skb)
{
	return tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_ACK;
}

__u16 get_packet_rst(struct sk_buff *skb)
{
	return tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_RST;
}

// forge tcp packets which have been caught in the local-out hook
int forge_lo_tcp_packet(struct sk_buff *skb, conn_entry_metadata_t *p_metadata, int from_http_client, int from_http_server, int from_ftp_client, int from_ftp_server, int from_smtp_client, int from_smtp_server)
{
	if (from_http_client || from_ftp_client || from_smtp_client) // if we got the packet from our fake client in the proxy, we need to replace the source address with the real client's source address
	{
		ip_hdr(skb)->saddr = p_metadata->client_ip;
	}
	if (from_http_server) // if we got the packet from our fake http server in the proxy, we need to replace the source address with the real server's source address and also the port (to 80)
	{
		ip_hdr(skb)->saddr = p_metadata->server_ip;
		tcp_hdr(skb)->source = HTTP_PORT_BE;
	}
	if (from_ftp_server) // if we got the packet from our fake ftp server in the proxy, we need to replace the source address with the real server's source address and also the port (to 21)
	{
		ip_hdr(skb)->saddr = p_metadata->server_ip;
		tcp_hdr(skb)->source = FTP_PORT_BE;
	}

	if (from_smtp_server) // if we got the packet from our fake smtp server in the proxy, we need to replace the source address with the real server's source address and also the port (to 25)
	{
		ip_hdr(skb)->saddr = p_metadata->server_ip;
		tcp_hdr(skb)->source = SMTP_PORT_BE;
	}

	return update_checksum(skb); // update the checksum of the forged packet
}

// forge tcp packets which have been caught in the pre-routing hook
int forge_pr_tcp_packet(struct sk_buff *skb, int from_http_client, int from_http_server, int from_ftp_client, int from_ftp_server, int from_smtp_client, int from_smpt_server)
{
	if (from_http_client) // if we got the packet from the http client, we redirect it to http proxy
	{
		ip_hdr(skb)->daddr = FAKE_SERVER_ADDR_BE;
		tcp_hdr(skb)->dest = HTTP_MITM_PORT_BE;
	}
	if (from_http_server) // if we got the packet from the http server, we redirect it to the http proxy only by changing the dest address because the dest port is already of the proxy
	{
		ip_hdr(skb)->daddr = FAKE_CLIENT_ADDR_BE;
	}
	if (from_ftp_client) // if we got the packet from the ftp client, we redirect it to ftp proxy
	{
		ip_hdr(skb)->daddr = FAKE_SERVER_ADDR_BE;
		tcp_hdr(skb)->dest = FTP_MITM_PORT_BE;
	}
	if (from_ftp_server) // if we got the packet from the ftp server, we redirect it to the ftp proxy only by changing the dest address because the dest port is already of the proxy
	{
		ip_hdr(skb)->daddr = FAKE_CLIENT_ADDR_BE;
	}
	if (from_smtp_client) // if we got the packet from the smtp client, we redirect it to smtp proxy
	{
		ip_hdr(skb)->daddr = FAKE_SERVER_ADDR_BE;
		tcp_hdr(skb)->dest = SMTP_MITM_PORT_BE;
	}
	if (from_smtp_server) // if we got the packet from the smtp server, we redirect it to the smtp proxy only by changing the dest address because the dest port is already of the proxy
	{
		ip_hdr(skb)->daddr = FAKE_CLIENT_ADDR_BE;
	}
	return update_checksum(skb); // update the checksum of the forged packet
}

// update the checksum of the forged packet
int update_checksum(struct sk_buff *skb)
{
	struct iphdr *ip_header = ip_hdr(skb);
	struct tcphdr *tcp_header;
	int tcplen;

	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum_valid = 0;

	if (skb_linearize(skb) < 0)
	{
		return 0;
	}

	ip_header = ip_hdr(skb);
	tcp_header = tcp_hdr(skb);
	tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
	tcp_header->check = 0;
	tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));
	return 1;
}

conn_entry_metadata_t create_conn_metadata(struct sk_buff *skb, __be32 original_src_ip, __be16 original_src_port, int from_http_client, int from_ftp_client, int from_smtp_client)
{
	conn_entry_metadata_t metadata;
	metadata.client_ip = original_src_ip;
	metadata.client_port = original_src_port;
	metadata.server_ip = ip_hdr(skb)->daddr;
	metadata.server_port = tcp_hdr(skb)->dest;
	metadata.forged_client_port = 0;
	metadata.random_ftp_data_port = 0; // this is relevant only for ftp

	if (from_http_client)
	{
		metadata.type = TCP_CONN_HTTP;
	}
	else if (from_ftp_client)
	{
		metadata.type = TCP_CONN_FTP;
	}
	else if (from_smtp_client)
	{
		metadata.type = TCP_CONN_SMTP;
	}
	else
	{
		metadata.type = TCP_CONN_OTHER;
	}

	return metadata;
}

conn_entry_metadata_t *retrieve_matching_metadata_of_packet(struct sk_buff *skb)
{
	conn_entry_node *conn_node;
	__be32 src_ip, dst_ip;
	__be16 src_port, dst_port;
	src_ip = ip_hdr(skb)->saddr;
	dst_ip = ip_hdr(skb)->daddr;

	src_port = tcp_hdr(skb)->source;
	dst_port = tcp_hdr(skb)->dest;

	conn_node = find_matching_conn_entry_node(src_ip, src_port, dst_ip, dst_port);
	if (conn_node)
	{
		return &conn_node->conn_entry.metadata; // metadata of the matching connection entry
	}
	return NULL;
}
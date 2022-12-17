#include "fw_conntab.h"
#include "fw_log.h"

struct list_head conn_tab = LIST_HEAD_INIT(conn_tab); // the head of the connection table linked list
int num_conn_entries = 0; // holdes the total current number of connection entries

// clears the connection table - deletes each entry, freeing the memory, and zeros the connection entries counter
void free_conn_tab(void) {
	conn_entry_node *conn_node, *tmp;
	list_for_each_entry_safe(conn_node, tmp, &conn_tab, list) {
			list_del(&conn_node->list);
			kfree(conn_node);
	}
	num_conn_entries = 0;
}

void remove_conn_node(conn_entry_node* conn_node) {
	list_del(&conn_node->list);
	--num_conn_entries;
}

// gets a connection entry and adds it to the connection table (allocates a new node for it and adds it)
void add_conn_entry(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, state_t state) {
	conn_entry_node* conn_node = kmalloc(sizeof(conn_entry_node), GFP_KERNEL);
	conn_node->conn_entry.src_ip = src_ip;
	conn_node->conn_entry.src_port = src_port;
	conn_node->conn_entry.dst_ip = dst_ip;
	conn_node->conn_entry.dst_port = dst_port;
	conn_node->conn_entry.state = state;
	list_add_tail(&conn_node->list, &conn_tab);
	++num_conn_entries;
}


int update_conn_tab_with_new_connection(struct sk_buff* skb) {
	struct iphdr *hdr;
	__be32 src_ip, dst_ip;
	__be16 src_port, dst_port;
	hdr = ip_hdr(skb);
	src_ip = hdr->saddr;
	dst_ip = hdr->daddr;
	src_port = tcp_hdr(skb)->source;
	dst_port = tcp_hdr(skb)->dest;

	if (find_matching_conn_entry_node(src_ip, src_port, dst_ip, dst_port)) { // there is already a record for this connection
		return 0;
	}

	add_conn_entry(src_ip, src_port, dst_ip, dst_port, SYN_RECEIVED);
	return 1;
}


conn_entry_node* find_matching_conn_entry_node(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port) {
	conn_entry_node *conn_node;
	conn_entry_t conn_entry;

	// iterates over the connection table and searches for a match
	list_for_each_entry(conn_node, &conn_tab, list) {
		conn_entry = conn_node->conn_entry;
		if (((src_ip == conn_entry.src_ip) &&
			(src_port == conn_entry.src_port) &&
			(dst_ip == conn_entry.dst_ip) &&
			(dst_port == conn_entry.dst_port))
			||									// we check both "sides" because we keep a single entry for an entire connection
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

//TODO remove printk in submittion
int update_conn_entry_state(conn_entry_node* conn_node, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __u16 pkt_syn, __u16 pkt_fin, __u16 pkt_rst) {
	conn_entry_t* p_conn_entry = &conn_node->conn_entry;
	bool is_client = src_ip == p_conn_entry->src_ip;
	bool is_server = !is_client;
	
	if (pkt_rst) {
		remove_conn_node(conn_node); // remove the conn_node from the dynamic connection table because RESET connection has been sent
		printk(KERN_INFO "RST");
	}
	
	switch (p_conn_entry->state)
	{
	case SYN_RECEIVED:
		if (is_server && pkt_syn) {
			printk(KERN_INFO "SYN_RECEIVED -> SYN_ACK_RECEIVED\n");
			p_conn_entry->state = SYN_ACK_RECEIVED;
			return 1;
		}
		break;
	case SYN_ACK_RECEIVED:
		if (is_client) {
			p_conn_entry->state = ESTABLISHED;
			printk(KERN_INFO "SYN_ACK_RECEIVED -> ESTABLISHED\n");
			return 1;
		}
		break;
	case ESTABLISHED:
		if (!pkt_fin) {
			printk(KERN_INFO "ESTABLISHED -> ESTABLISHED\n");
			return 1;
		} else {
			printk(KERN_INFO "ESTABLISHED -> FIN_1_RECEIVED\n");
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
		if (is_server && pkt_fin) {
			printk(KERN_INFO "FIN_1_RECEIVED -> FIN_2_RECEIVED\n");
			p_conn_entry->state = FIN_2_RECEIVED;
			return 1;
		}
	case FIN_2_RECEIVED:
		if (is_client) {
			printk(KERN_INFO "FIN_2_RECEIVED -> CLOSED\n");
			remove_conn_node(conn_node); // remove the conn_node from the dynamic connection table because there is no more connection between the two endopints
			return 1;
		}
	}
	return 0;
}


// searches a matching connection table entry for the acked-TCP packet, writes it in the log and returns the verdict for the packet
int match_conn_entries(struct sk_buff* skb) {
	conn_entry_node *conn_node;
	__u8 action;
	reason_t reason;
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
	if (conn_node == NULL) {
		action = NF_DROP;
		reason = REASON_NO_MATCHING_CONN_ENTRY;
	} else {
		if (update_conn_entry_state(conn_node, src_ip, src_port, dst_ip, dst_port, get_packet_syn(skb), get_packet_fin(skb), get_packet_rst(skb))) {
			action = NF_ACCEPT;
			reason = REASON_MATCHING_CONN_ENTRY;
		} else {
			action = NF_DROP;
			reason = REASON_NO_MATCHING_CONN_ENTRY;
		}
	}
	update_log(skb, reason, action); // update the log with the input packet
	return action;
}


__u16 get_packet_syn(struct sk_buff* skb) {
	return tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_SYN;
}


__u16 get_packet_fin(struct sk_buff* skb) {
	return tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_FIN;
}


__u16 get_packet_ack(struct sk_buff* skb) {
	return tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_ACK;
}

__u16 get_packet_rst(struct sk_buff* skb) {
	return tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_RST;
}

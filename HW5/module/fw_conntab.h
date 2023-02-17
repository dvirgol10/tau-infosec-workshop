#ifndef _FW_CONNTAB_H_
#define _FW_CONNTAB_H_

#include "fw_kernel.h"
#include <linux/list.h>

// a node in the linked list which holds all of the connection table entries (each node contains a single entry)
typedef struct
{
	struct list_head list;
	conn_entry_t conn_entry;
} conn_entry_node;

extern struct list_head conn_tab; // the head of the connection table linked list
extern int num_conn_entries;	  // holdes the total current number of connection entries

// clears the connection table - deletes each entry, freeing the memory, and zeros the connection entries counter
void free_conn_tab(void);

// gets a connection entry and adds it to the connection table (allocates a new node for it and adds it)
void add_conn_entry(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, state_t state, conn_entry_metadata_t metadata);

int update_conn_tab_with_new_connection(struct sk_buff *skb, conn_entry_metadata_t metadata);

conn_entry_node *find_matching_conn_entry_node(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port);

// update the tcp state of a connection entry
int update_conn_entry_state(conn_entry_node *conn_node, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __u16 pkt_syn, __u16 pkt_fin, __u16 pkt_rst);

// searches a matching connection table entry for the acked-TCP packet, writes it in the log and returns the verdict for the packet
verdict_t match_conn_entries(struct sk_buff *skb, int to_update_log);

__u16 get_packet_syn(struct sk_buff *skb);

__u16 get_packet_fin(struct sk_buff *skb);

__u16 get_packet_ack(struct sk_buff *skb);

__u16 get_packet_rst(struct sk_buff *skb);

conn_entry_metadata_t *retrieve_matching_metadata_of_packet(struct sk_buff *skb);

// creates a metadata struct for the provided connection
conn_entry_metadata_t create_conn_metadata(struct sk_buff *skb, __be32 original_src_ip, __be16 original_src_port, int from_http_client, int from_ftp_client, int from_smtp_client);

// forge tcp packets which have been caught in the pre-routing hook
int forge_pr_tcp_packet(struct sk_buff *skb, int from_http_client, int from_http_server, int from_ftp_client, int from_ftp_server, int from_smtp_client, int from_smtp_server);

// forge tcp packets which have been caught in the local-out hook
int forge_lo_tcp_packet(struct sk_buff *skb, conn_entry_metadata_t *p_metadata, int from_http_client, int from_http_server, int from_ftp_client, int from_ftp_server, int from_smtp_client, int from_smtp_server);

// update the checksum of the forged packet
int update_checksum(struct sk_buff *skb);

#endif // _FW_CONNTAB_H_
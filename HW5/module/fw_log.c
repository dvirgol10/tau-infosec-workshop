#include "fw_log.h"


struct list_head log_list = LIST_HEAD_INIT(log_list); // the head of the log linked list
int num_logs = 0; // holdes the total current number of log rows

// clears the log list - deletes each row, freeing the memory, and zeros the log row counter
void free_log_list(void) {
	log_list_node *log_node, *tmp;
	list_for_each_entry_safe(log_node, tmp, &log_list, list) {
			list_del(&log_node->list);
			kfree(log_node);
	}
	num_logs = 0;
}


// gets a log row and adds it to the linked list (allocates a new node for it and adds it)
void add_log_row(log_row_t log_row) {
	log_list_node* log_node = kmalloc(sizeof(log_list_node), GFP_KERNEL);
	log_node->log_row = log_row;
	list_add_tail(&log_node->list, &log_list);
	++num_logs;
}


// gets the packet's sk_buff structure, the reason and the verdict, and updates the log appropriately:
//	if there is already a log row which matches the input - increment the counter and update the timestamp
//	otherwise, create a new log row for the input packet
void update_log(struct sk_buff* skb, reason_t reason, __u8 action) {
	struct timespec64 tv;
	struct iphdr *hdr;
	log_list_node *log_node;
	unsigned char protocol;
	__be32 src_ip, dst_ip;
	unsigned short src_port, dst_port;
	log_row_t log_row;

	ktime_get_real_ts64(&tv); // get the current timestamp

	// initialize some variables to compare to those of the current log rows
	hdr = ip_hdr(skb);
	src_ip = hdr->saddr;
	dst_ip = hdr->daddr;
	protocol = hdr->protocol;
	switch (protocol) {
		case PROT_ICMP: src_port = dst_port = 0; break;
		case PROT_TCP: src_port = ntohs(tcp_hdr(skb)->source); dst_port = ntohs(tcp_hdr(skb)->dest); break;
		case PROT_UDP: src_port = ntohs(udp_hdr(skb)->source); dst_port = ntohs(udp_hdr(skb)->dest); break;
		default: return; // we should never reach this
	}
	
	// iterates over the log list and searches for a match
	list_for_each_entry(log_node, &log_list, list) {
		log_row = log_node->log_row;
		if ((protocol == log_row.protocol) &&
			(action == log_row.action) &&
			(src_ip == log_row.src_ip) &&
			(dst_ip == log_row.dst_ip) &&
			(src_port == log_row.src_port) &&
			(dst_port == log_row.dst_port) &&
			(reason == log_row.reason))
		{ // if a match was found, increment the counter and update the timestamp
			log_node->log_row.count += 1;
			log_node->log_row.timestamp = tv.tv_sec;
			return;
		}
	}
	// if there is no compatible log row, we need to create a new one and add it to the list
	log_row.timestamp = tv.tv_sec;
	log_row.protocol = protocol;
	log_row.action = action;
	log_row.src_ip = src_ip;
	log_row.dst_ip = dst_ip;
	log_row.src_port = src_port;
	log_row.dst_port = dst_port;
	log_row.reason = reason;
	log_row.count = 1;
	add_log_row(log_row);
}

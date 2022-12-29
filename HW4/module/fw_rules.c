#include "fw_rules.h"
#include "fw_log.h"
#include "fw_conntab.h"

// a table which stores all the active rules
rule_t rule_table[MAX_RULES];
int num_rules; // holdes the total number of active rules in the table. < MAX_RULES


// clears the rule table (zeros its memory)
void reset_rule_table(void) {
	memset(rule_table, 0, RULE_TABLE_SIZE);
}


int validate_prefix_mask_and_size(__be32 prefix_mask, __u8 prefix_size) {
	// The left hand side is a calculation results in a little endian numeric prefix mask which matches the prefix_size
	// so we compare it to the little endian representation of prefix_mask
	return (1ULL << 32) - (1ULL << (32 - prefix_size)) == ntohl(prefix_mask);
}


int validate_rule(rule_t* rule) {
	if (!strlen(rule->rule_name)) {
		return 0; // A rule has to have a name
	}

	// direction
	switch (rule->direction) {
		case DIRECTION_IN: case DIRECTION_OUT: case DIRECTION_ANY: break;
		default: return 0;
	}

	// checks that the prefix_mask and prefix_size match
	if (!validate_prefix_mask_and_size(rule->src_prefix_mask, rule->src_prefix_size) ||
		!validate_prefix_mask_and_size(rule->dst_prefix_mask, rule->dst_prefix_size)) {
		return 0;
	}

	// protocol
	switch (rule->protocol) {
		case PROT_ICMP: case PROT_TCP: case PROT_UDP: case PROT_OTHER: case PROT_ANY: break;
		default: return 0;
	}

	// ack
	switch (rule->ack) {
		case ACK_NO: case ACK_YES: case ACK_ANY: break;
		default: return 0;
	}

	// action
	switch (rule->action) {
		case NF_ACCEPT: case NF_DROP: break;
		default: return 0;
	}
	return 1;
}


// checks if there is a match between the rule's port and packet's port - considering the special values ("any" and "above 1023")
int match_port(unsigned short rule_port, __be16 pkt_port) {
	switch (rule_port) {
		case PORT_ANY: return 1;
		case PORT_ABOVE_1023: if (ntohs(pkt_port) >= 1023) { return 1; } return 0;
		default: return rule_port == ntohs(pkt_port);
	}
}


// checks if there is a match between the rule's ack and packet's ack
int match_ack(ack_t rule_ack, __u16 pkt_ack) {
	switch (rule_ack) {
		case ACK_NO: return !pkt_ack; 
		case ACK_YES: return pkt_ack;
		case ACK_ANY: return 1;
	}
	return 1; // we should never reach this
}


// checks if the tcp header components of the packet match to those which resides in the rule.
// those components are the source and destination ports, as well as the ack bit
int match_tcphdr(rule_t* rule, struct tcphdr* hdr, struct sk_buff* skb) {
	return match_port(rule->src_port, hdr->source) && match_port(rule->dst_port, hdr->dest) && match_ack(rule->ack, get_packet_ack(skb));
}


// checks if the udp header components of the packet match to those which resides in the rule.
// those components are the source and destination ports
int match_udphdr(rule_t* rule, struct udphdr* hdr) {
	return match_port(rule->src_port, hdr->source) && match_port(rule->dst_port, hdr->dest);
}


// checks if the ip of the packets matches the ip of the rule, considering the subnet mask
int match_ip(__be32 rule_ip, __be32 pkt_ip, __be32 prefix_mask) {
	return (rule_ip & prefix_mask) == (pkt_ip & prefix_mask);
}


// checks if the ip header components of the packet match to those which resides in the rule.
// those components are the source and destination ip addresses, as well as the packet's protocol
int match_iphdr(rule_t* rule, struct iphdr* hdr) {
	if (!match_ip(rule->src_ip, hdr->saddr, rule->src_prefix_mask) || !match_ip(rule->dst_ip, hdr->daddr, rule->dst_prefix_mask)) {
		return 0;
	}
	
	if ((rule->protocol != PROT_ANY) && (rule->protocol != hdr->protocol)) {
		return 0;
	}
	return 1;
}


// checks if the input rule matches the current packet
int match_rule(rule_t* rule, struct sk_buff* skb, direction_t pkt_direction) {
	struct iphdr *hdr;
	
	// direction
	if ((rule->direction != DIRECTION_ANY) && (rule->direction != pkt_direction)) {
		return 0;
	}
	
	// ip header part
	hdr = ip_hdr(skb);
	if (!match_iphdr(rule, hdr)) {
		return 0;
	}

	// according to the packet's protocol, choose the correct matching method
	switch (hdr->protocol) {
		case PROT_ICMP: return 1;
		case PROT_TCP: return match_tcphdr(rule, tcp_hdr(skb), skb);
		case PROT_UDP: return match_udphdr(rule, udp_hdr(skb));
		default: return 0; // we should never reach this
	}
	return 1; // we should never reach this
}


// checks if the packet is a loopback packet
int is_loopback(struct sk_buff* skb) {
	return match_ip(LOOPBACK_ADDR_BE, ip_hdr(skb)->daddr, 255);
}


// checks if the packet is a christmas tree packet
int is_xmas(struct sk_buff* skb) {
	return ip_hdr(skb)->protocol == PROT_TCP &&
	(tcp_flag_word(tcp_hdr(skb)) & (TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH));
}


// searches a matching rule for the packet, writes it in the log and returns the verdict for the packet
verdict_t match_rules(struct sk_buff* skb, direction_t pkt_direction, int to_update_conn_tab_and_log) {
	int i;
	verdict_t verdict;
	conn_entry_metadata_t metadata;
	metadata.type = TCP_CONN_OTHER;
	if (is_xmas(skb)) {
		verdict.action = NF_DROP; // we drop every christmas tree packet
		verdict.reason = REASON_XMAS_PACKET;
	} else {
		for (i = 0; i < num_rules; i++) {
			if (match_rule(&rule_table[i], skb, pkt_direction)) {
				verdict.action = rule_table[i].action; // the verdict is by the action written in the rule
				verdict.reason = i; // the reason is the index of the rule
				if (to_update_conn_tab_and_log && ip_hdr(skb)->protocol == PROT_TCP && verdict.action == NF_ACCEPT) { // if this is a TCP packet we want to update the dynamic connection table appropriately
					if (get_packet_syn(skb)) {
						if (!update_conn_tab_with_new_connection(skb, metadata)) { // if the update has failed, meaning if there was already such connection between the endpoints
							verdict.action = NF_DROP;
							verdict.reason = REASON_ALREADY_HAS_CONN_ENTRY;
						}
					} else {
						verdict.action = NF_DROP;
						verdict.reason = REASON_ILLEGAL_VALUE;
					}
				}
				break; // we want the first matching rule
			}
		}
		if (i == num_rules) { // we didn't find any matching rule
			verdict.action = NF_DROP;
			verdict.reason = REASON_NO_MATCHING_RULE;
		}
	}
	if (to_update_conn_tab_and_log || verdict.action == NF_DROP) {
		update_log(skb, verdict.reason, verdict.action); // update the log with the input packet
	}
	return verdict;
}
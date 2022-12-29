#ifndef _FW_RULES_H_
#define _FW_RULES_H_

#include "fw_kernel.h"

// a table which stores all the active rules
extern rule_t rule_table[MAX_RULES];
extern int num_rules; // holdes the total number of active rules in the table. < MAX_RULES


// clears the rule table (zeros its memory)
void reset_rule_table(void);

int validate_prefix_mask_and_size(__be32 prefix_mask, __u8 prefix_size);

int validate_rule(rule_t* rule);

// checks if there is a match between the rule's port and packet's port - considering the special values ("any" and "above 1023")
int match_port(unsigned short rule_port, __be16 pkt_port);

// checks if there is a match between the rule's ack and packet's ack
int match_ack(ack_t rule_ack, __u16 pkt_ack);

// checks if the tcp header components of the packet match to those which resides in the rule.
// those components are the source and destination ports, as well as the ack bit
int match_tcphdr(rule_t* rule, struct tcphdr* hdr, struct sk_buff* skb);

// checks if the udp header components of the packet match to those which resides in the rule.
// those components are the source and destination ports
int match_udphdr(rule_t* rule, struct udphdr* hdr);

// checks if the ip of the packets matches the ip of the rule, considering the subnet mask
int match_ip(__be32 rule_ip, __be32 pkt_ip, __be32 prefix_mask);

// checks if the ip header components of the packet match to those which resides in the rule.
// those components are the source and destination ip addresses, as well as the packet's protocol
int match_iphdr(rule_t* rule, struct iphdr* hdr);

// checks if the input rule matches the current packet
int match_rule(rule_t* rule, struct sk_buff* skb, direction_t pkt_direction);

// checks if the packet is a loopback packet
int is_loopback(struct sk_buff* skb);

// checks if the packet is a christmas tree packet
int is_xmas(struct sk_buff* skb);

// searches a matching rule for the packet, writes it in the log and returns the verdict for the packet
verdict_t match_rules(struct sk_buff* skb, direction_t pkt_direction, int to_update_conn_tab_and_log);


#endif // _FW_RULES_H_
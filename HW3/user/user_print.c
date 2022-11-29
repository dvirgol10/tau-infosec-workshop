#include "user_print.h"


void print_error_message_and_exit(char* err_msg) {
	fprintf(stderr, "\n[!] Error: %s\n", err_msg);
	exit(1);
}


// prefix size should be at most 32
void validate_prefix_size(unsigned int prefix_size) {
	if (prefix_size > 32) {
		print_error_message_and_exit("There is some ip prefix size which isn't valid");
	}
}


// converts 'direction' field to string (for printing)
char* direction_to_s(direction_t direction) {
	switch (direction) {
		case DIRECTION_IN: return "in";
		case DIRECTION_OUT: return "out";
		case DIRECTION_ANY: return "any";
	}
	print_error_message_and_exit("There is some direction which isn't valid");
	return ""; // we should never reach this
}


// converts 'protocol' field to string (for printing)
char* log_protocol_to_s(unsigned char protocol) {
	switch (protocol) {
		case PROT_ICMP: return "icmp";
		case PROT_TCP: return "tcp";
		case PROT_UDP: return "udp";
		case PROT_OTHER: return "other";
		case PROT_ANY: return "any";
	}
	print_error_message_and_exit("There is some protocol which isn't valid");
	return ""; // we should never reach this
}


// converts 'protocol' field to string (for printing)
char* rule_protocol_to_s(unsigned char protocol) {
	switch (protocol) {
		case PROT_ICMP: return "ICMP";
		case PROT_TCP: return "TCP";
		case PROT_UDP: return "UDP";
		case PROT_OTHER: return "other";
		case PROT_ANY: return "any";
	}
	print_error_message_and_exit("There is some protocol which isn't valid");
	return ""; // we should never reach this
}


// converts 'ack' field to string (for printing)
char* ack_to_s(ack_t ack) {
	switch (ack) {
		case ACK_NO: return "no";
		case ACK_YES: return "yes";
		case ACK_ANY: return "any";
	}
	print_error_message_and_exit("There is some ack which isn't valid");
	return ""; // we should never reach this
}


// converts 'action' field to string (for printing)
char* action_to_s(unsigned char	action) {
	switch (action) {
		case NF_DROP: return "drop";
		case NF_ACCEPT: return "accept";
	}
	print_error_message_and_exit("There is some action which isn't valid");
	return ""; // we should never reach this
}


// gets an ip address represented as a (big endian) number, and prints its octat representation (1.2.3.4)
void print_ip(unsigned int ip) {
	struct in_addr addr;
	addr.s_addr = ip;
	printf("%s", inet_ntoa(addr));
}


// prints the 'port' field, considering the special values of any and above 1023
void print_port(unsigned short port) {
	switch (port) {
		case PORT_ANY: printf("any "); break;
		case PORT_ABOVE_1023: printf(">1023 "); break;
		default: printf("%hu ", port); break;
	}
}


// prints entire rule, as needed for "show_rules" command
void print_rule(rule_t* rule) {
	char rule_name[21];
	strncpy(rule_name, rule->rule_name, 20);
	rule_name[20] = 0; // a null-byte for the name (maybe all of its 20 chars are used)

	printf("%s %s ", rule_name, direction_to_s(rule->direction)); // prints the rule name and the direction field
	
	// prints the src_ip address, represented like "1.2.3.4/8", or "any" (if needed)
	validate_prefix_size(rule->src_prefix_size);
	if (rule->src_prefix_size) {
		print_ip(rule->src_ip);
		printf("/%hhu ", rule->src_prefix_size);
	} else {
		printf("any "); // every ip address is in the "subnet" of prefix_size=0, so it's equivalent to "any"
	}

	// prints the dst_ip address, represented like "1.2.3.4/8", or "any" (if needed)
	validate_prefix_size(rule->dst_prefix_size);
	if (rule->dst_prefix_size) {
		print_ip(rule->dst_ip);
		printf("/%hhu ", rule->dst_prefix_size);
	} else {
		printf("any "); // every ip address is in the "subnet" of prefix_size=0, so it's equivalent to "any"
	}

	printf("%s ", rule_protocol_to_s(rule->protocol)); // prints the protocol field

	print_port(rule->src_port); // prints src_port
	print_port(rule->dst_port); // prints dst_port
	
	printf("%s %s\n", ack_to_s(rule->ack), action_to_s(rule->action)); // prints the ack and action fields of the current rule
}


// prints numeric timestamp in its desired string representation
void print_timestamp(unsigned long timestamp) { // helper source: https://man7.org/linux/man-pages/man3/localtime.3p.html
	struct tm tmstmp;
	localtime_r(&timestamp, &tmstmp);
	printf("%02d/%02d/%02d %02d:%02d:%02d",
		tmstmp.tm_mday, tmstmp.tm_mon, tmstmp.tm_year-100, tmstmp.tm_hour, tmstmp.tm_min, tmstmp.tm_sec);
}


// prints the reason: if the reason is an index - prints it, otherwise prints our predefined reasons
void print_reason(reason_t reason) {
	if ((int)reason < 0) {
		switch (reason) {
			case REASON_FW_INACTIVE: printf("REASON_FW_INACTIVE "); return;
			case REASON_NO_MATCHING_RULE: printf("REASON_NO_MATCHING_RULE "); return;
			case REASON_XMAS_PACKET: printf("REASON_XMAS_PACKET "); return;
			case REASON_ILLEGAL_VALUE: printf("REASON_ILLEGAL_VALUE "); return;
		}
		print_error_message_and_exit("There is some reason which isn't valid");
	} else {
		printf("%d ", (int)reason);
	}
}


// prints an entire log row
void print_log_row(log_row_t* log_row) {
	print_timestamp(log_row->timestamp);
	printf("\t\t");
	print_ip(log_row->src_ip);
	printf("\t\t");
	print_ip(log_row->dst_ip);
	printf("\t\t");

	printf("%hu\t\t%hu\t\t%s\t\t%s\t",
		log_row->src_port, log_row->dst_port, log_protocol_to_s(log_row->protocol), action_to_s(log_row->action));
	
	print_reason(log_row->reason);
	
	printf("\t\t\t\t%u\n", log_row->count);
}
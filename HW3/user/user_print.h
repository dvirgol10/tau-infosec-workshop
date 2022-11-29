#ifndef _USER_PRINT_H_
#define _USER_PRINT_H_

#include "fw_user.h"


void print_error_message_and_exit(char* err_msg);

// prefix size should be at most 32
void validate_prefix_size(unsigned int prefix_size);

// converts 'direction' field to string (for printing)
char* direction_to_s(direction_t direction);

// converts 'protocol' field to string (for printing)
char* log_protocol_to_s(unsigned char protocol);

// converts 'protocol' field to string (for printing)
char* rule_protocol_to_s(unsigned char protocol);

// converts 'ack' field to string (for printing)
char* ack_to_s(ack_t ack);

// converts 'action' field to string (for printing)
char* action_to_s(unsigned char	action);

// gets an ip address represented as a (big endian) number, and prints its octat representation (1.2.3.4)
void print_ip(unsigned int ip);

// prints the 'port' field, considering the special values of any and above 1023
void print_port(unsigned short port);

// prints entire rule, as needed for "show_rules" command
void print_rule(rule_t* rule);

// prints numeric timestamp in its desired string representation
void print_timestamp(unsigned long timestamp);

// prints the reason: if the reason is an index - prints it, otherwise prints our predefined reasons
void print_reason(reason_t reason);

// prints an entire log row
void print_log_row(log_row_t* log_row);


#endif // _USER_PRINT_H_
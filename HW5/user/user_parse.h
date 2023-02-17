#ifndef _USER_PARSE_H_
#define _USER_PARSE_H_

#include "fw_user.h"

// a table which stores all the rules (if "show_rules" then the rules of the firewall, and if "load_rules" then the user's rules)
rule_t rule_table[MAX_RULES];
int num_rules; // holdes the total number of rules in the table. < MAX_RULES


// checks whether the input string contains only digits or not 
int only_digits_string(char* str);

// gets a string representation of an ip address ("1.2.3.4") and returns appropriate big endian number representing it
unsigned int ip_convert_string_to_network(char* ip_addr);

// takes a string representation of an ip address and its subnet mask (of the form "1.2.3.4/8") and fills the correct number values in the input pointers
int parse_ip_string(char* ip_addr_and_prefix_size, unsigned int* ip, unsigned char* prefix_size, unsigned int* prefix_mask);

// gets a port's string representation (as written in a rule) and filles the right value in the pointer
int parse_port_string(char* port_string, unsigned short* port);

// parsing the input rule with index 'rule_num'
int parse_rule(char* rule_line, int rule_num);

// parse the input rules file into our rule_table (for "load_rules" command)
void parse_rules_file(char* path_to_rules_file);


#endif // _USER_PARSE_H_
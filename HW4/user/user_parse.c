#include "user_parse.h"
#include "user_print.h"

// checks whether the input string contains only digits or not
int only_digits_string(char *str)
{
	int i;
	for (i = 0; i < strlen(str); i++)
	{
		if (!isdigit(str[i]))
		{
			return 0;
		}
	}
	return 1;
}

// gets a string representation of an ip address ("1.2.3.4") and returns appropriate big endian number representing it
unsigned int ip_convert_string_to_network(char *ip_addr)
{
	struct in_addr inp;
	if (!inet_aton(ip_addr, &inp))
	{
		print_error_message_and_exit("There is an invalid ip address");
	}
	return inp.s_addr;
}

// takes a string representation of an ip address and its subnet mask (of the form "1.2.3.4/8") and fills the correct number values in the input pointers
int parse_ip_string(char *ip_addr_and_prefix_size, unsigned int *ip, unsigned char *prefix_size, unsigned int *prefix_mask)
{
	struct in_addr inp;
	long maybe_prefix_size;
	char *ip_save_ptr;

	if (!strcmp(ip_addr_and_prefix_size, "any"))
	{
		*ip = 0;
		*prefix_size = 0; // as written in a previous comment, ip address "any" is equivalent to prefix_size of 0
		*prefix_mask = 0;
		return 1;
	}

	char *token = strtok_r(ip_addr_and_prefix_size, "/", &ip_save_ptr); // split to the pure ip address part ("1.2.3.4") and mask part
	if (!token)
	{
		return 0;
	}
	*ip = ip_convert_string_to_network(token);

	if (!(token = strtok_r(NULL, "/", &ip_save_ptr)))
	{
		return 0;
	}
	if (!only_digits_string(token))
	{ // the mask part should contain only digits
		return 0;
	}
	maybe_prefix_size = strtol(token, NULL, 10); // converts the mask string to mask number
	// according to the man page of strtol, if overflow occurs, strtol() returns LONG_MAX
	if (maybe_prefix_size == LONG_MAX || maybe_prefix_size < 0)
	{
		return 0;
	}
	validate_prefix_size(maybe_prefix_size);
	*prefix_size = (unsigned char)maybe_prefix_size;

	if (token = strtok_r(NULL, " ", &ip_save_ptr))
	{ // if there is more data in the line despite we've completed the ip address string, it's invalid
		return 0;
	}
	*prefix_mask = (unsigned int)htonl((1ULL << 32) - (1ULL << (32 - *prefix_size))); // A calculation results in a numeric prefix_mask which matches the prefix_size
	return 1;
}

// gets a port's string representation (as written in a rule) and filles the right value in the pointer
int parse_port_string(char *port_string, unsigned short *port)
{
	long maybe_port;
	if (!strcmp(port_string, "any"))
	{
		*port = PORT_ANY;
		return 1;
	}
	if (!strcmp(port_string, ">1023"))
	{ // this is the string of "above 1023"
		*port = PORT_ABOVE_1023;
		return 1;
	}
	if (!only_digits_string(port_string))
	{ // if the port != "any" and != ">1023", it should be a number
		return 0;
	}

	maybe_port = strtol(port_string, NULL, 10); // converts the port string to port number
	// according to the man page of strtol, if overflow occurs, strtol() returns LONG_MAX
	if (maybe_port == LONG_MAX || maybe_port < 0)
	{
		return 0;
	}
	*port = (unsigned short)maybe_port;

	return 1;
}

// parsing the input rule with index 'rule_num'
int parse_rule(char *rule_line, int rule_num)
{
	char *rule_token_save_ptr;
	rule_t *rule = &rule_table[rule_num];

	// rule_name
	char *token = strtok_r(rule_line, " ", &rule_token_save_ptr);
	if (!token)
	{
		return 0;
	}
	if (strlen(token) > 20)
	{ // names will be no longer than 20 chars
		return 0;
	}
	strncpy(rule->rule_name, token, 20);

	// direction
	if (!(token = strtok_r(NULL, " ", &rule_token_save_ptr)))
	{
		return 0;
	}
	if (!strcmp(token, "in"))
	{
		rule->direction = DIRECTION_IN;
	}
	else if (!strcmp(token, "out"))
	{
		rule->direction = DIRECTION_OUT;
	}
	else if (!strcmp(token, "any"))
	{
		rule->direction = DIRECTION_ANY;
	}
	else
	{
		return 0;
	}

	// src_port, src_prefix_size, src_prefix_mask
	if (!(token = strtok_r(NULL, " ", &rule_token_save_ptr)))
	{
		return 0;
	}
	if (!parse_ip_string(token, &rule->src_ip, &rule->src_prefix_size, &rule->src_prefix_mask))
	{
		return 0;
	}

	// dst_ip, dst_prefix_size, dst_prefix_mask
	if (!(token = strtok_r(NULL, " ", &rule_token_save_ptr)))
	{
		return 0;
	}
	if (!parse_ip_string(token, &rule->dst_ip, &rule->dst_prefix_size, &rule->dst_prefix_mask))
	{
		return 0;
	}

	// protocol
	if (!(token = strtok_r(NULL, " ", &rule_token_save_ptr)))
	{
		return 0;
	}
	if (!strcmp(token, "ICMP"))
	{
		rule->protocol = PROT_ICMP;
	}
	else if (!strcmp(token, "TCP"))
	{
		rule->protocol = PROT_TCP;
	}
	else if (!strcmp(token, "UDP"))
	{
		rule->protocol = PROT_UDP;
	}
	else if (!strcmp(token, "any"))
	{
		rule->protocol = PROT_ANY;
	}
	else
	{
		rule->protocol = PROT_OTHER;
	}

	// src_port
	if (!(token = strtok_r(NULL, " ", &rule_token_save_ptr)))
	{
		return 0;
	}
	if (!parse_port_string(token, &rule->src_port))
	{
		return 0;
	}

	// dst_port
	if (!(token = strtok_r(NULL, " ", &rule_token_save_ptr)))
	{
		return 0;
	}
	if (!parse_port_string(token, &rule->dst_port))
	{
		return 0;
	}

	// ack
	if (!(token = strtok_r(NULL, " ", &rule_token_save_ptr)))
	{
		return 0;
	}
	if (!strcmp(token, "no"))
	{
		rule->ack = ACK_NO;
	}
	else if (!strcmp(token, "yes"))
	{
		rule->ack = ACK_YES;
	}
	else if (!strcmp(token, "any"))
	{
		rule->ack = ACK_ANY;
	}
	else
	{
		return 0;
	}

	// action
	if (!(token = strtok_r(NULL, " ", &rule_token_save_ptr)))
	{
		return 0;
	}
	if (!strcmp(token, "drop") || !strcmp(token, "drop\n"))
	{
		rule->action = NF_DROP;
	}
	else if (!strcmp(token, "accept") || !strcmp(token, "accept\n"))
	{
		rule->action = NF_ACCEPT;
	}
	else
	{
		return 0;
	}

	if (token = strtok_r(NULL, " ", &rule_token_save_ptr))
	{ // if there is more data in the line despite we've completed the rule, it's invalid
		return 0;
	}
	return 1;
}

// parse the input rules file into our rule_table (for "load_rules" command)
void parse_rules_file(char *path_to_rules_file)
{ // helper source for reading lines: https://stackoverflow.com/a/3501681
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int rule_num = 0;

	fp = fopen(path_to_rules_file, "r");
	if (!fp)
	{
		print_error_message_and_exit("The path to rules file isn't valid");
	}

	while (getline(&line, &len, fp) != -1)
	{
		if (rule_num >= MAX_RULES)
		{ // we allow only MAX_RULES rules
			fclose(fp);
			if (line)
			{
				free(line);
			}
			print_error_message_and_exit("There are too many rules");
		}
		if (!parse_rule(line, rule_num))
		{ // parse each rule separately
			print_error_message_and_exit("There is an invalid rule");
		}
		++rule_num;
	}

	num_rules = rule_num; // save the total number of rules

	fclose(fp);
	if (line)
	{
		free(line);
	}
}

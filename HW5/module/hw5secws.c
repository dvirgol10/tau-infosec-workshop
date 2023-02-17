#include "fw_kernel.h"
#include "fw_rules.h"
#include "fw_log.h"
#include "fw_conntab.h"

MODULE_LICENSE("GPL");

static int major_number;
static struct class *fw_class;
static struct device *rules_device;
static struct device *log_device;
static struct device *conn_tab_device;

int next_log_row_index_to_be_read = -1;			// stores the index of the next log_row which may be read (for optimization)
log_list_node *next_log_node_to_be_read = NULL; // stores the address of the next log row's node which may be read (for optimization)

unsigned int pr_handle_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int register_pr_hook(void);
void unregister_pr_hook(void);
unsigned int lo_handle_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int register_lo_hook(void);
void unregister_lo_hook(void);
ssize_t read_logs(struct file *filp, char *buff, size_t count, loff_t *offp);
ssize_t load_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t reset_logs(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t show_conns(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t show_metadata(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t update_metadata(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
void cleanup(void);

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = read_logs};

static struct nf_hook_ops pre_routing_nfho;
static struct nf_hook_ops local_out_nfho;

// init attributes
static DEVICE_ATTR(rules, S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP, show_rules, load_rules);
static DEVICE_ATTR(reset, S_IWUSR | S_IWGRP, NULL, reset_logs);
static DEVICE_ATTR(conns, S_IRUSR | S_IRGRP, show_conns, NULL);
static DEVICE_ATTR(proxy, S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP, show_metadata, update_metadata);

// the local-out hook: here we send packets from our proxy programs to the real endpoints
unsigned int lo_handle_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	verdict_t verdict;
	if (skb->protocol != htons(ETH_P_IP))
	{
		return NF_ACCEPT; // we accept any non-IPv4 packet without logging it
	}

	// special handling for TCP packets
	if (ip_hdr(skb)->protocol == PROT_TCP)
	{
		__be16 my_src_port = tcp_hdr(skb)->source;
		__be16 my_dst_port = tcp_hdr(skb)->dest;
		int from_http_client = my_dst_port == HTTP_PORT_BE;
		int from_http_server = my_src_port == HTTP_MITM_PORT_BE;
		int from_ftp_client = my_dst_port == FTP_PORT_BE;
		int from_ftp_server = my_src_port == FTP_MITM_PORT_BE;
		int from_smtp_client = my_dst_port == SMTP_PORT_BE;
		int from_smtp_server = my_src_port == SMTP_MITM_PORT_BE;
		conn_entry_metadata_t *p_metadata = retrieve_matching_metadata_of_packet(skb);

		if (!p_metadata) // if we don't have a matching metadata structure for the packet we need to drop it
		{
			return NF_DROP;
		}

		switch (p_metadata->type)
		{
		case TCP_CONN_HTTP:
		case TCP_CONN_FTP:
		case TCP_CONN_SMTP:
			break;
		case TCP_CONN_OTHER:
			return NF_ACCEPT; // we don't need to forge a TCP packet other than HTTP and FTP
		}

		verdict = match_conn_entries(skb, 1); // we match the packet to a connection entry (and there we also update the state)

		// forge the packet before sending it
		if (!forge_lo_tcp_packet(skb, p_metadata, from_http_client, from_http_server, from_ftp_client, from_ftp_server, from_smtp_client, from_smtp_server))
		{
			verdict.action = NF_DROP;
			verdict.reason = REASON_COULDNT_UPDATE_CHECKSUM;
			update_log(skb, verdict.reason, verdict.action);
		}

		return verdict.action;
	}

	return NF_ACCEPT;
}

// I used the following source: https://infosecwriteups.com/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e
int register_lo_hook(void)
{
	local_out_nfho.hook = (nf_hookfn *)lo_handle_packet;
	local_out_nfho.hooknum = NF_INET_LOCAL_OUT;
	local_out_nfho.pf = PF_INET;
	local_out_nfho.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &local_out_nfho);
}

void unregister_lo_hook(void)
{
	nf_unregister_net_hook(&init_net, &local_out_nfho);
}

// this is the hook function, gets a packet in the "pre routing" hook, documents it in the log if needed, and returns the verdict for the packet
unsigned int pr_handle_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *hdr;
	direction_t pkt_direction;
	verdict_t verdict;
	// determine the direction of the packet
	if (!strcmp(state->in->name, IN_NET_DEVICE_NAME))
	{
		pkt_direction = DIRECTION_OUT;
	}
	else
	{
		pkt_direction = DIRECTION_IN;
	}

	if (skb->protocol != htons(ETH_P_IP))
	{
		return NF_ACCEPT; // we accept any non-IPv4 packet without logging it
	}

	hdr = ip_hdr(skb);
	switch (hdr->protocol)
	{
	case PROT_ICMP:
	case PROT_TCP:
	case PROT_UDP:
		break;
	default:
		return NF_ACCEPT; // we accept any non-TCP, UDP and ICMP protocol without logging it
	}

	// special handling for TCP packets
	if (hdr->protocol == PROT_TCP)
	{
		__be16 original_src_port = tcp_hdr(skb)->source;
		__be16 original_dst_port = tcp_hdr(skb)->dest;
		__be32 original_src_ip = ip_hdr(skb)->saddr;
		int from_http_client = original_dst_port == HTTP_PORT_BE;
		int from_http_server = original_src_port == HTTP_PORT_BE;
		int from_ftp_client = original_dst_port == FTP_PORT_BE;
		int from_ftp_server = original_src_port == FTP_PORT_BE;
		int from_smtp_client = original_dst_port == SMTP_PORT_BE;
		int from_smtp_server = original_src_port == SMTP_PORT_BE;
		conn_entry_metadata_t metadata;

		if (get_packet_ack(skb))
		{
			// if the packet is a HTTP or FTP or SMTP packet we have to forge it to redirect it to one of our proxy programs
			if (from_http_client || from_http_server || from_ftp_client || from_ftp_server || from_smtp_client || from_smtp_server)
			{
				if (!forge_pr_tcp_packet(skb, from_http_client, from_http_server, from_ftp_client, from_ftp_server, from_smtp_client, from_smtp_server))
				{
					verdict.action = NF_DROP;
					verdict.reason = REASON_COULDNT_UPDATE_CHECKSUM;
					update_log(skb, verdict.reason, verdict.action);
				}
			}

			verdict = match_conn_entries(skb, 1); // we match the packet to a connection entry (and there we also update the state)
			return verdict.action;
		}
		else // if we don't have an ack in the packet, meaning it's a SYN packet
		{
			if (from_http_client || from_ftp_client || from_smtp_client) // if the packet is from http or ftp or smtp client we need to redirect it to the proxy and create the appropriate connection table entries for the forged connections
			{
				verdict = match_rules(skb, pkt_direction, 0); // we first check if in according to the rules we need to drop or accept the packet
				if (verdict.action == NF_DROP)
				{
					return NF_DROP;
				}
				else
				{
					// we create an initial metadata structure for the new packet
					metadata = create_conn_metadata(skb, original_src_ip, original_src_port, from_http_client, from_ftp_client, from_smtp_client);

					if (!forge_pr_tcp_packet(skb, from_http_client, from_http_server, from_ftp_client, from_ftp_server, from_smtp_client, from_smtp_server)) // after that we forge it
					{
						verdict.action = NF_DROP;
						verdict.reason = REASON_COULDNT_UPDATE_CHECKSUM;
					}
					else if (get_packet_syn(skb))
					{ // if this is a TCP packet we want to update the dynamic connection table appropriately
						if (!update_conn_tab_with_new_connection(skb, metadata))
						{ // if the update has failed, meaning if there was already such connection between the endpoints
							verdict.action = NF_DROP;
							verdict.reason = REASON_ALREADY_HAS_CONN_ENTRY;
						}
					}
					else
					{
						verdict.action = NF_DROP;
						verdict.reason = REASON_ILLEGAL_VALUE;
					}
					update_log(skb, verdict.reason, verdict.action); // update the log with the input packet
					return verdict.action;
				}
			}
			else // if the packet isn't a HTTP or FTP or SMTP packet
			{
				verdict = match_conn_entries(skb, 0); // we first check if the SYN packet has an entry in the connection table. In this case it means that this is a packet for our forged connection of the proxy, or the syn packet is for the data connection of FTP
				if (verdict.action == NF_ACCEPT)
				{													 // it means that this packet is for the active connection of FTP or forged connection of our proxy with the real server
					update_log(skb, verdict.reason, verdict.action); // update the log with the input packet
				}
				else
				{
					verdict = match_rules(skb, pkt_direction, 1); // otherwise, we just match the new SYN packet to the rules (beacause this is the general behaviour for new TCP connections)
				}
				return verdict.action;
			}
		}
	}

	if (is_loopback(skb))
	{ // we accept any loopback packet without logging it
		return NF_ACCEPT;
	}

	return match_rules(skb, pkt_direction, 1).action;
}

// I used the following source: https://infosecwriteups.com/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e
int register_pr_hook(void)
{
	pre_routing_nfho.hook = (nf_hookfn *)pr_handle_packet;
	pre_routing_nfho.hooknum = NF_INET_PRE_ROUTING;
	pre_routing_nfho.pf = PF_INET;
	pre_routing_nfho.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &pre_routing_nfho);
}

void unregister_pr_hook(void)
{
	nf_unregister_net_hook(&init_net, &pre_routing_nfho);
}

// the function invokes when the user requests to read the logs, read each log_row separately
ssize_t read_logs(struct file *filp, char *buff, size_t count, loff_t *offp)
{
	int i = 0;
	log_list_node *log_node;

	unsigned int minor_num = iminor(file_inode(filp));
	if (minor_num != MINOR_LOG)
	{
		return -EFAULT; // if the device we are trying to read from is not the device of the logs, we don't allow reading
	}

	if (count != sizeof(log_row_t))
	{
		return -EINVAL;
	}

	if (*offp >= num_logs * sizeof(log_row_t))
	{ // if the user has finished to read all of the log, we zero the file offset and return EOF
		*offp = 0;
		return 0; // EOF
	}

	if (*offp != next_log_row_index_to_be_read)
	{ // if our optimization isn't relevant (because, for example, there are multiple reading users)
		list_for_each_entry(log_node, &log_list, list)
		{ // iterates through the log list to find the right log row matching the offset
			if (*offp == i * sizeof(log_row_t))
			{
				next_log_row_index_to_be_read = i;
				next_log_node_to_be_read = log_node;
				break;
			}
		}
	}

	if (copy_to_user(buff, &next_log_node_to_be_read->log_row, sizeof(log_row_t)))
	{ // send the data to the user through 'copy_to_user'
		return -EFAULT;
	}

	// update the helper variables (file offset, and the variables for the optimization)
	*offp += sizeof(log_row_t);
	++next_log_row_index_to_be_read;
	next_log_node_to_be_read = list_next_entry(next_log_node_to_be_read, list);

	return sizeof(log_row_t);
}

ssize_t reset_logs(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	free_log_list();
	return count;
}

// loads the rules from the user (it's invoked when the user loads a new rule table to the module)
ssize_t load_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int i, tmp_num_rules;

	if (count % sizeof(rule_t))
	{
		printk(KERN_INFO "Invalid rule table length");
		return 0;
	}

	// we first validates all the rules and just after that we update our active rule table
	tmp_num_rules = count / sizeof(rule_t);
	if (tmp_num_rules > MAX_RULES)
	{
		printk(KERN_INFO "Rule table is too big");
		return 0;
	}
	for (i = 0; i < tmp_num_rules; i++)
	{
		if (!validate_rule(&((rule_t *)buf)[i]))
		{
			printk(KERN_INFO "There is an invalid rule: #%d\n", i);
			return 0; // the input rule table is invalid
		}
	}

	// the input rule table is valid
	num_rules = tmp_num_rules;
	reset_rule_table();
	memcpy(rule_table, buf, num_rules * sizeof(rule_t));
	return count;
}

// copy the rule table to the user
ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf)
{
	memcpy(buf, rule_table, RULE_TABLE_SIZE);
	return RULE_TABLE_SIZE;
}

// copy the connection table to the user
ssize_t show_conns(struct device *dev, struct device_attribute *attr, char *buf)
{
	conn_entry_node *conn_node;

	list_for_each_entry(conn_node, &conn_tab, list)
	{ // iterates through the connection table list to send the data to the user
		memcpy(buf, &conn_node->conn_entry, sizeof(conn_entry_t));
		buf += sizeof(conn_entry_t);
	}
	return num_conn_entries * sizeof(conn_entry_t);
}

// copy the valuable metadata structures to the user (we deliver only the metadata entries of HTTP or FTP)
ssize_t show_metadata(struct device *dev, struct device_attribute *attr, char *buf)
{
	conn_entry_node *conn_node;
	int i = 0;
	list_for_each_entry(conn_node, &conn_tab, list)
	{ // iterates through the connection table list to send the metadata entries to the user
		if (conn_node->conn_entry.metadata.type != TCP_CONN_OTHER)
		{
			memcpy(buf, &conn_node->conn_entry.metadata, sizeof(conn_entry_metadata_t));
			buf += sizeof(conn_entry_metadata_t);
			++i;
		}
	}
	return i * sizeof(conn_entry_metadata_t);
}

// we get a metadata entry from the user and update all the matching metadata entries in the connection table (the user updates only the forged source port and/or the random port for ftp data connection)
ssize_t update_metadata(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	conn_entry_node *conn_node;
	conn_entry_t *p_conn_entry;
	conn_entry_metadata_t metadata;
	if (count != sizeof(conn_entry_metadata_t))
	{
		printk(KERN_INFO "Invalid metadata entry length");
		return 0;
	}

	memcpy(&metadata, buf, sizeof(conn_entry_metadata_t));
	list_for_each_entry(conn_node, &conn_tab, list)
	{ // iterates through the connection table list to find matching entry
		p_conn_entry = &conn_node->conn_entry;
		if ((metadata.type == p_conn_entry->metadata.type) &&
			(metadata.client_ip == p_conn_entry->metadata.client_ip) &&
			(metadata.client_port == p_conn_entry->metadata.client_port) &&
			(metadata.server_ip == p_conn_entry->metadata.server_ip) &&
			(metadata.server_port == p_conn_entry->metadata.server_port))
		{
			p_conn_entry->metadata = metadata; // update the metadata
			if (p_conn_entry->dst_ip == p_conn_entry->metadata.server_ip)
			{ // meaning that the entry is of our proxy and the destination is the server, so we update the source port of the connection entry to be the new forged port
				p_conn_entry->src_port = metadata.forged_client_port;
			}
		}
	}

	// if the random ftp data port is different from 0, it means that our proxy viewed a PORT command and we need to add a connection table entry for the FTP data connection with the new port
	if (metadata.random_ftp_data_port != 0 && metadata.type == TCP_CONN_FTP)
	{
		// the source of the data connection is the server with port 20, and the destination is the client with the port we got from the proxy
		add_conn_entry(metadata.server_ip, FTP_DATA_SRC_PORT, metadata.client_ip, metadata.random_ftp_data_port, WAITING_TO_START, metadata);
	}
	return count;
}

// do the cleanup of the devices
void cleanup(void)
{
	device_remove_file(conn_tab_device, (const struct device_attribute *)&dev_attr_proxy.attr);
	device_remove_file(conn_tab_device, (const struct device_attribute *)&dev_attr_conns.attr);
	device_remove_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
	device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
	device_destroy(fw_class, MKDEV(major_number, MINOR_CONN_TAB));
	class_destroy(fw_class);
	unregister_chrdev(major_number, CLASS_NAME);
}

int __init init_module_firewall(void)
{
	int retval;

	// create char device
	major_number = register_chrdev(0, DEVICE_NAME, &fops);
	if (major_number < 0)
	{
		return -1;
	}

	// create class
	fw_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(fw_class))
	{
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(fw_class);
	}

	// create rules device
	rules_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);
	if (IS_ERR(rules_device))
	{
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(rules_device);
	}

	// create log device
	log_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, DEVICE_NAME_LOG);
	if (IS_ERR(log_device))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(rules_device);
	}

	// create connection table device
	conn_tab_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_CONN_TAB), NULL, DEVICE_NAME_CONN_TAB);
	if (IS_ERR(conn_tab_device))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(rules_device);
	}

	// create rules device file attributes
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONN_TAB));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return -1;
	}

	// create log device file attributes
	if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONN_TAB));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return -1;
	}

	// create connection table device file attributes
	if (device_create_file(conn_tab_device, (const struct device_attribute *)&dev_attr_conns.attr))
	{
		device_remove_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONN_TAB));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return -1;
	}

	// create connection table device file attributes
	if (device_create_file(conn_tab_device, (const struct device_attribute *)&dev_attr_proxy.attr))
	{
		device_remove_file(conn_tab_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_remove_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONN_TAB));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return -1;
	}

	// register hook
	retval = register_pr_hook();
	if (retval < 0)
	{
		printk(KERN_INFO "Failed to register the pr hook");
		cleanup();
		return retval;
	}
	retval = register_lo_hook();
	if (retval < 0)
	{
		printk(KERN_INFO "Failed to register the lo hook");
		unregister_pr_hook();
		cleanup();
		return retval;
	}

	reset_rule_table();

	return 0;
}

void __exit cleanup_module_firewall(void)
{
	// unregister hooks
	unregister_pr_hook();
	unregister_lo_hook();

	free_log_list();
	free_conn_tab();

	cleanup();
}

module_init(init_module_firewall);
module_exit(cleanup_module_firewall);

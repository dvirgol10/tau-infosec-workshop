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


int next_log_row_index_to_be_read = -1; // stores the index of the next log_row which may be read (for optimization)
log_list_node *next_log_node_to_be_read = NULL; // stores the address of the next log row's node which may be read (for optimization)


unsigned int handle_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
ssize_t read_logs(struct file *filp, char *buff, size_t count, loff_t *offp);
int register_pr_hook(void);
void unregister_pr_hook(void);
ssize_t load_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t reset_logs(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t show_conns(struct device *dev, struct device_attribute *attr, char *buf);
void cleanup(void);

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = read_logs
};

static struct nf_hook_ops pre_routing_nfho;


// init attributes 
static DEVICE_ATTR(rules, S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP , show_rules, load_rules);
static DEVICE_ATTR(reset, S_IWUSR | S_IWGRP , NULL, reset_logs);
static DEVICE_ATTR(conns, S_IRUSR | S_IRGRP , show_conns, NULL);


// this is the hook function, gets a packet in the "pre routing" hook, documents it in the log if needed, and returns the verdict for the packet
unsigned int handle_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct iphdr *hdr;
	direction_t pkt_direction;
	// determine the direction of the packet
	if (!strcmp(state->in->name, IN_NET_DEVICE_NAME)) {
		pkt_direction = DIRECTION_OUT;
	} else {
		pkt_direction = DIRECTION_IN;
	}

	if (skb->protocol != htons(ETH_P_IP)) {
		return NF_ACCEPT; // we accept any non-IPv4 packet without logging it
	} else if (is_loopback(skb)) { // we accept any loopback packet without logging it
		return NF_ACCEPT;
	}
	
	hdr = ip_hdr(skb);
	switch (hdr->protocol) {
		case PROT_ICMP: case PROT_TCP: case PROT_UDP: break;
		default: return NF_ACCEPT; // we accept any non-TCP, UDP and ICMP protocol without logging it
	}

	if ((hdr->protocol == PROT_TCP) && get_packet_ack(skb)) {
		return match_conn_entries(skb);
	}

	return match_rules(skb, pkt_direction);
}

// I used the following source: https://infosecwriteups.com/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e
int register_pr_hook(void) {
	pre_routing_nfho.hook = (nf_hookfn*) handle_packet;
	pre_routing_nfho.hooknum = NF_INET_PRE_ROUTING;
	pre_routing_nfho.pf = PF_INET;
	pre_routing_nfho.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &pre_routing_nfho);
}


void unregister_pr_hook(void) {
	nf_unregister_net_hook(&init_net, &pre_routing_nfho);
}

// the function invokes when the user requests to read the logs, read each log_row separately
ssize_t read_logs(struct file *filp, char *buff, size_t count, loff_t *offp) {
	int i = 0;
	log_list_node *log_node;

	unsigned int minor_num = iminor(file_inode(filp));
	if (minor_num != MINOR_LOG) {
		return -EFAULT; // if the device we are trying to read from is not the device of the logs, we don't allow reading
	}
	
	if (count != sizeof(log_row_t)) {
		return -EINVAL;
	}
	
	if (*offp >= num_logs * sizeof(log_row_t)) { // if the user has finished to read all of the log, we zero the file offset and return EOF 
		*offp = 0;
		return 0; // EOF
	}

	if (*offp != next_log_row_index_to_be_read) { // if our optimization isn't relevant (because, for example, there are multiple reading users)
		list_for_each_entry(log_node, &log_list, list) { // iterates through the log list to find the right log row matching the offset
			if (*offp == i * sizeof(log_row_t)) {
				next_log_row_index_to_be_read = i;
				next_log_node_to_be_read = log_node;
				break;
			}
		}
	}

	if (copy_to_user(buff, &next_log_node_to_be_read->log_row, sizeof(log_row_t))) { // send the data to the user through 'copy_to_user'
		return -EFAULT;
	}

	// update the helper variables (file offset, and the variables for the optimization)
	*offp += sizeof(log_row_t);
	++next_log_row_index_to_be_read;
	next_log_node_to_be_read = list_next_entry(next_log_node_to_be_read, list);

	return sizeof(log_row_t);
}


ssize_t reset_logs(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	free_log_list();
	return count;
}


// loads the rules from the user (it's invoked when the user loads a new rule table to the module)
ssize_t load_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	int i, tmp_num_rules;

	if (count % sizeof(rule_t)) {
		printk(KERN_INFO "Invalid rule table length");
		return 0;
	}

	// we first validates all the rules and just after that we update our active rule table
	tmp_num_rules = count / sizeof(rule_t);
	if (tmp_num_rules > MAX_RULES) {
		printk(KERN_INFO "Rule table is too big");
		return 0;
	}
	for (i = 0; i < tmp_num_rules; i++) {
		if (!validate_rule(&((rule_t*)buf)[i])) {
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
ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf) {
	memcpy(buf, rule_table, RULE_TABLE_SIZE);
	return RULE_TABLE_SIZE;
}


// copy the connection table to the user
ssize_t show_conns(struct device *dev, struct device_attribute *attr, char *buf) {
	conn_entry_node *conn_node;
	
	list_for_each_entry(conn_node, &conn_tab, list) { // iterates through the connection table list to send the data to the user
		memcpy(buf, &conn_node->conn_entry, sizeof(conn_entry_t));
		buf += sizeof(conn_entry_t);
	}
	return num_conn_entries * sizeof(conn_entry_t);
}


// do the cleanup of the devices
void cleanup(void) {
	device_remove_file(conn_tab_device, (const struct device_attribute*) &dev_attr_conns.attr); 
	device_remove_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr); 
	device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
	device_destroy(fw_class,  MKDEV(major_number, MINOR_RULES));
	device_destroy(fw_class,  MKDEV(major_number, MINOR_LOG));
	device_destroy(fw_class, MKDEV(major_number, MINOR_CONN_TAB));
	class_destroy(fw_class);
	unregister_chrdev(major_number, CLASS_NAME);
}


int __init init_module_firewall(void) {
	int retval;

	// create char device
	major_number = register_chrdev(0, DEVICE_NAME, &fops);
	if (major_number < 0) {
		return -1;
	}

	// create class
	fw_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(fw_class)) {
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(fw_class);
	}

	// create rules device
	rules_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);
	if (IS_ERR(rules_device)) {
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(rules_device);
	}

	// create log device
	log_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, DEVICE_NAME_LOG);
	if (IS_ERR(log_device)) {
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(rules_device);
	}

	// create connection table device
	conn_tab_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_CONN_TAB), NULL, DEVICE_NAME_CONN_TAB);
	if (IS_ERR(conn_tab_device)) {
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(rules_device);
	}

	// create rules device file attributes
	if (device_create_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr)) {
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONN_TAB));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return -1;
	}

	// create log device file attributes
	if (device_create_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr)) {
		device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONN_TAB));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return -1;
	}

	// create connection table device file attributes
	if (device_create_file(conn_tab_device, (const struct device_attribute*) &dev_attr_conns.attr)) {
		device_remove_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr); 
		device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONN_TAB));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return -1;
	}

	// register hook
	retval = register_pr_hook();
	if (retval < 0) {
		printk(KERN_INFO "Failed to register the hook");
		cleanup();
		return retval;
	}

	reset_rule_table();

	return 0;
}


void __exit cleanup_module_firewall(void) {
	// unregister hooks
	unregister_pr_hook();

	free_log_list();
	free_conn_tab();

	cleanup();
}


module_init(init_module_firewall);
module_exit(cleanup_module_firewall);


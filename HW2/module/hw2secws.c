#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/netfilter_ipv4.h>

#define DEVICE_NAME "hw2secws_device"
#define CLASS_NAME "hw2secws_class"

#define ACCEPTED_PACKET_MSG "*** Packet Accepted ***"
#define DROPPED_PACKET_MSG "*** Packet Dropped ***"


MODULE_LICENSE("GPL");

static int major_number;
static struct class *hw2secws_class;
static struct device *hw2secws_device;

static unsigned int accepted_packets_cnt = 0;
static unsigned int dropped_packets_cnt = 0;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

static struct nf_hook_ops local_in_nfho;
static struct nf_hook_ops local_out_nfho;
static struct nf_hook_ops forward_nfho;


void notify_accepted_packet(void) {
	printk(KERN_INFO ACCEPTED_PACKET_MSG);
}


void notify_blocked_packet(void) {
	printk(KERN_INFO DROPPED_PACKET_MSG);
}


unsigned int accept_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	notify_accepted_packet();
	accepted_packets_cnt += 1;
	return NF_ACCEPT;
}


unsigned int drop_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	notify_blocked_packet();
	dropped_packets_cnt += 1;
	return NF_DROP;
}


/* I used the following source: https://infosecwriteups.com/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e*/
void register_local_conn_hook(void) {
	local_in_nfho.hook = (nf_hookfn*) accept_packet;
	local_in_nfho.hooknum = NF_INET_LOCAL_IN;
	local_in_nfho.pf = PF_INET;
	local_in_nfho.priority = NF_IP_PRI_FIRST;
	
	local_out_nfho.hook = (nf_hookfn*) accept_packet;
	local_out_nfho.hooknum = NF_INET_LOCAL_OUT;
	local_out_nfho.pf = PF_INET;
	local_out_nfho.priority = NF_IP_PRI_FIRST;
	
	nf_register_net_hook(&init_net, &local_in_nfho);
	nf_register_net_hook(&init_net, &local_out_nfho);
}


/* I used the following source: https://infosecwriteups.com/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e*/
void register_global_conn_hook(void) {
	forward_nfho.hook = (nf_hookfn*) drop_packet;
	forward_nfho.hooknum = NF_INET_FORWARD;
	forward_nfho.pf = PF_INET;
	forward_nfho.priority = NF_IP_PRI_FIRST;
	
	nf_register_net_hook(&init_net, &forward_nfho);
}


void unregister_local_conn_hook(void) {
	nf_unregister_net_hook(&init_net, &local_in_nfho);
	nf_unregister_net_hook(&init_net, &local_out_nfho);
}


void unregister_global_conn_hook(void) {
	nf_unregister_net_hook(&init_net, &forward_nfho);
}


ssize_t show_accepted_packets_cnt(struct device *dev, struct device_attribute *attr, char *buf) {
	return scnprintf(buf, PAGE_SIZE, "%u\n", accepted_packets_cnt);
}


ssize_t store_accepted_packets_cnt(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	int tmp;
	if (sscanf(buf, "%u", &tmp) == 1) {
		accepted_packets_cnt = tmp;
	}
	return count;
}


ssize_t show_dropped_packets_cnt(struct device *dev, struct device_attribute *attr, char *buf) {
	return scnprintf(buf, PAGE_SIZE, "%u\n", dropped_packets_cnt);
}


ssize_t store_dropped_packets_cnt(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	int tmp;
	if (sscanf(buf, "%u", &tmp) == 1) {
		dropped_packets_cnt = tmp;
	}
	return count;
}


static DEVICE_ATTR(accepted_packets_cnt_attr, S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP , show_accepted_packets_cnt, store_accepted_packets_cnt);
static DEVICE_ATTR(dropped_packets_cnt_attr,  S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP, show_dropped_packets_cnt, store_dropped_packets_cnt);


int __init init_module_hw2secws(void) {
	// create char device
	major_number = register_chrdev(0, DEVICE_NAME, &fops);
	if (major_number < 0) {
		return -1;
	}

	// create class
	hw2secws_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(hw2secws_class)) {
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(hw2secws_class);
	}

	// create device
	hw2secws_device = device_create(hw2secws_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
	if (IS_ERR(hw2secws_device)) {
		class_destroy(hw2secws_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(hw2secws_device);
	}

	// create device file attributes
	if (device_create_file(hw2secws_device, (const struct device_attribute*) &dev_attr_accepted_packets_cnt_attr.attr)) {
		device_destroy(hw2secws_class, MKDEV(major_number, 0));
		class_destroy(hw2secws_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return -1;
	}
	if (device_create_file(hw2secws_device, (const struct device_attribute*) &dev_attr_dropped_packets_cnt_attr.attr)) {
		device_remove_file(hw2secws_device, (const struct device_attribute*) &dev_attr_accepted_packets_cnt_attr.attr); 
		device_destroy(hw2secws_class, MKDEV(major_number, 0));
		class_destroy(hw2secws_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return -1;
	}

	// register hooks
	register_local_conn_hook();
	register_global_conn_hook();
	return 0;
}


void __exit cleanup_module_hw2secws(void) {
	// unregister hooks
	unregister_local_conn_hook();
	unregister_global_conn_hook();

	// cleanup
	device_remove_file(hw2secws_device, (const struct device_attribute*) &dev_attr_dropped_packets_cnt_attr.attr); 
	device_remove_file(hw2secws_device, (const struct device_attribute*) &dev_attr_accepted_packets_cnt_attr.attr); 
	device_destroy(hw2secws_class, MKDEV(major_number, 0));
	class_destroy(hw2secws_class);
	unregister_chrdev(major_number, DEVICE_NAME);
}


module_init(init_module_hw2secws);
module_exit(cleanup_module_hw2secws);


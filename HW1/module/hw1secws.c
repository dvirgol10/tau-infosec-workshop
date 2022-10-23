#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>

#define ACCEPTED_PACKET_MSG "*** Packet Accepted ***"
#define DROPPED_PACKET_MSG "*** Packet Dropped ***"

MODULE_LICENSE("GPL");

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
	return NF_ACCEPT;
}


unsigned int drop_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	notify_blocked_packet();
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


int __init init_module_hw1secws(void) {
	register_local_conn_hook();
	register_global_conn_hook();
	return 0;
}


void __exit cleanup_module_hw1secws(void) {
	unregister_local_conn_hook();
	unregister_global_conn_hook();
}


module_init(init_module_hw1secws);
module_exit(cleanup_module_hw1secws);


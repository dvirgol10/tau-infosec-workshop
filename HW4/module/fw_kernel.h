#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <net/tcp.h>


// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           	= -1,
	REASON_NO_MATCHING_RULE      	= -2,
	REASON_XMAS_PACKET           	= -4,
	REASON_ILLEGAL_VALUE         	= -6,
	REASON_MATCHING_CONN_ENTRY 		= -8,
	REASON_NO_MATCHING_CONN_ENTRY 	= -10,
	REASON_ALREADY_HAS_CONN_ENTRY	= -12,
} reason_t;
	

// auxiliary strings, for your convenience
#define DEVICE_NAME					"fw"
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"fw_log"
#define DEVICE_NAME_CONN_TAB		"conns"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"enp0s8"
#define OUT_NET_DEVICE_NAME			"enp0s9"

// auxiliary values, for your convenience
#define IP_VERSION			(4)
#define PORT_ANY			(0)
#define PORT_ABOVE_1023		(1023)
#define MAX_RULES			(50)
#define RULE_TABLE_SIZE 	(MAX_RULES * sizeof(rule_t))
#define HTTP_PORT_BE		(10752)		// 10752 is 42 in BE	//(20480)		// 20480 is 80 in BE
#define FTP_PORT_BE			(5376)		// 5376 is 21 in BE
#define HTTP_MITM_PORT_BE	(8195)		// 8195 is 800 in BE
#define FTP_MITM_PORT_BE	(53760)		// 53760 is 210 in BE
#define FTP_DATA_SRC_PORT	(5120)		// 5120 is 20 in BE
#define LOOPBACK_ADDR_BE	(16777343) 	// 16777343 is "127.0.0.1" in BE, 255 is "255.0.0.0" in BE
#define FAKE_SERVER_ADDR_BE	(50397450)	// 50397450 is "10.1.1.3"
#define FAKE_CLIENT_ADDR_BE	(50462986)	// 50462986 is "10.1.2.3"

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
	MINOR_CONN_TAB = 2,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

typedef struct {
	unsigned char  	action;
	reason_t		reason;
} verdict_t;

typedef enum {
	WAITING_TO_START,
	SYN_RECEIVED,
	SYN_ACK_RECEIVED,
	ESTABLISHED,
	FIN_1_RECEIVED,
	FIN_2_RECEIVED,
	/* CLOSED */					// instead of having a "closed" state, we simply remove the connection entry from the dynamic table after receiving ACK for the last FIN
} state_t;

typedef enum {
	TCP_CONN_HTTP 	= 0,
	TCP_CONN_FTP	= 1,
	TCP_CONN_OTHER	= 2,
} tcp_conn_type_t;

typedef struct {
	tcp_conn_type_t type;
	__be32 client_ip;
	__be16 client_port;
	__be32 server_ip;
	__be16 server_port;
	__be16 forged_client_port;
	__be16 random_ftp_data_port;
} conn_entry_metadata_t;

// connection table
typedef struct {
	__be32   				src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 					src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be32					dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 					dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	state_t     			state;
	conn_entry_metadata_t 	metadata;
} conn_entry_t;


#endif // _FW_H_
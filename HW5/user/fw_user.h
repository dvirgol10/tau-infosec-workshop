#ifndef _FW_H_
#define _FW_H_

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

// the protocols we will work with
typedef enum
{
	PROT_ICMP = 1,
	PROT_TCP = 6,
	PROT_UDP = 17,
	PROT_OTHER = 255,
	PROT_ANY = 143,
} prot_t;

// various reasons to be registered in each log entry
typedef enum
{
	REASON_FW_INACTIVE = -1,
	REASON_NO_MATCHING_RULE = -2,
	REASON_XMAS_PACKET = -4,
	REASON_ILLEGAL_VALUE = -6,
	REASON_MATCHING_CONN_ENTRY = -8,
	REASON_NO_MATCHING_CONN_ENTRY = -10,
	REASON_ALREADY_HAS_CONN_ENTRY = -12,
	REASON_COULDNT_UPDATE_CHECKSUM = -14,
} reason_t;

// auxiliary strings, for your convenience
#define DEVICE_NAME "fw"
#define DEVICE_NAME_RULES "rules"
#define DEVICE_NAME_LOG "fw_log"
#define DEVICE_NAME_CONN_TAB "conns"
#define CLASS_NAME "fw"
#define LOOPBACK_NET_DEVICE_NAME "lo"
#define IN_NET_DEVICE_NAME "enp0s8"
#define OUT_NET_DEVICE_NAME "enp0s9"

// auxiliary values, for your convenience
#define IP_VERSION (4)
#define PORT_ANY (0)
#define PORT_ABOVE_1023 (1023)
#define MAX_RULES (50)
#define RULE_TABLE_SIZE (MAX_RULES * sizeof(rule_t))
#define PAGE_SIZE (4096)
#define MAX_CONN_ENTRIES (PAGE_SIZE / sizeof(log_row_t))
#define NF_DROP (0)
#define NF_ACCEPT (1)

// device minor numbers, for your convenience
typedef enum
{
	MINOR_RULES = 0,
	MINOR_LOG = 1,
} minor_t;

typedef enum
{
	ACK_NO = 0x01,
	ACK_YES = 0x02,
	ACK_ANY = ACK_NO | ACK_YES,
} ack_t;

typedef enum
{
	DIRECTION_IN = 0x01,
	DIRECTION_OUT = 0x02,
	DIRECTION_ANY = DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct
{
	char rule_name[20]; // names will be no longer than 20 chars
	direction_t direction;
	unsigned int src_ip;
	unsigned int src_prefix_mask;  // e.g., 255.255.255.0 as int in the local endianness
	unsigned char src_prefix_size; // valid values: 0-32, e.g., /24 for the example above
								   // (the field is redundant - easier to print)
	unsigned int dst_ip;
	unsigned int dst_prefix_mask;  // as above
	unsigned char dst_prefix_size; // as above
	unsigned short src_port;	   // number of port or 0 for any or port 1023 for any port number > 1023
	unsigned short dst_port;	   // number of port or 0 for any or port 1023 for any port number > 1023
	unsigned char protocol;		   // values from: prot_t
	ack_t ack;					   // values from: ack_t
	unsigned char action;		   // valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct
{
	unsigned long timestamp; // time of creation/update
	unsigned char protocol;	 // values from: prot_t
	unsigned char action;	 // valid values: NF_ACCEPT, NF_DROP
	unsigned int src_ip;	 // if you use this struct in userspace, change the type to unsigned int
	unsigned int dst_ip;	 // if you use this struct in userspace, change the type to unsigned int
	unsigned short src_port; // if you use this struct in userspace, change the type to unsigned short
	unsigned short dst_port; // if you use this struct in userspace, change the type to unsigned short
	reason_t reason;		 // rule#index, or values from: reason_t
	unsigned int count;		 // counts this line's hits
} log_row_t;

typedef enum
{
	WAITING_TO_START,
	SYN_RECEIVED,
	SYN_ACK_RECEIVED,
	ESTABLISHED,
	FIN_1_RECEIVED,
	FIN_2_RECEIVED,
	/* CLOSED */ // instead of having a "closed" state, we simply remove the connection entry from the dynamic table after receiving ACK for the last FIN
} state_t;

typedef enum
{
	TCP_CONN_HTTP = 0,
	TCP_CONN_FTP = 1,
	TCP_CONN_SMTP = 2,
	TCP_CONN_OTHER = 3,
} tcp_conn_type_t;

typedef struct
{
	tcp_conn_type_t type;
	unsigned int client_ip;
	unsigned short client_port;
	unsigned int server_ip;
	unsigned short server_port;
	unsigned short forged_client_port;
	unsigned short random_ftp_data_port;
} conn_entry_metadata_t;

// connection table
typedef struct
{
	unsigned int src_ip;	 // if you use this struct in userspace, change the type to unsigned int
	unsigned short src_port; // if you use this struct in userspace, change the type to unsigned short
	unsigned int dst_ip;	 // if you use this struct in userspace, change the type to unsigned int
	unsigned short dst_port; // if you use this struct in userspace, change the type to unsigned short
	state_t state;
	conn_entry_metadata_t metadata;
} conn_entry_t;

#endif // _FW_H_
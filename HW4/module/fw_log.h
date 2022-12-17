#ifndef _FW_LOG_H_
#define _FW_LOG_H_

#include "fw_kernel.h"
#include <linux/list.h>

// a node in the linked list which holds all of the log rows (each node contains a single log row)
typedef struct {
	struct list_head list;
	log_row_t log_row;
} log_list_node;


extern struct list_head log_list; // the head of the log linked list
extern int num_logs; // holdes the total current number of log rows


// clears the log list - deletes each row, freeing the memory, and zeros the log row counter
void free_log_list(void);

// gets a log row and adds it to the linked list (allocates a new node for it and adds it)
void add_log_row(log_row_t log_row);

// gets the packet's sk_buff structure, the reason and the verdict, and updates the log appropriately:
//	if there is already a log row which matches the input - increment the counter and update the timestamp
//	otherwise, create a new log row for the input packet
void update_log(struct sk_buff* skb, reason_t reason, __u8 action);


#endif // _FW_LOG_H_
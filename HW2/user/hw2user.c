#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>


#define ATTRS_PATH "/sys/class/hw2secws_class/hw2secws_device/" 

static unsigned int accepted_packets_cnt;
static unsigned int dropped_packets_cnt;

void read_counter(const char *counter_attr_path, unsigned int *p_counter) {
	FILE *f;
	if (!(f = fopen(counter_attr_path, "r"))) {
		perror("fopen");
		exit(1);
	}

	if (fscanf(f, "%u", p_counter) != 1) {
		perror("fscanf");
		fclose(f);
		exit(1);
	}

	fclose(f);
}


void write_counter(const char *counter_attr_path, unsigned int *p_counter) {
	FILE *f;
	if (!(f = fopen(counter_attr_path, "w"))) {
		perror("fopen");
		exit(1);
	}

	if (fprintf(f, "%u\n", *p_counter) < 0) {
		perror("fprintf");
		fclose(f);
		exit(1);
	}

	fclose(f);
}


void read_counters() {
	read_counter(ATTRS_PATH "accepted_packets_cnt_attr", &accepted_packets_cnt);
	read_counter(ATTRS_PATH "dropped_packets_cnt_attr", &dropped_packets_cnt);
}


void write_counters() {
	write_counter(ATTRS_PATH "accepted_packets_cnt_attr", &accepted_packets_cnt);
	write_counter(ATTRS_PATH "dropped_packets_cnt_attr", &dropped_packets_cnt);
}

void print_packet_summary() {
	read_counters();
	printf("Firewall Packets Summary:\nNumber of accepted packets: %u\nNumber of dropped packets: %u\nTotal number of packets: %u\n", accepted_packets_cnt, dropped_packets_cnt, accepted_packets_cnt + dropped_packets_cnt);
}


void reset_counters() {
	accepted_packets_cnt = 0;
	dropped_packets_cnt = 0;
	write_counters();
}


int main(int argc, char *argv[]) {
	if (argc == 1) {
		print_packet_summary();
	} else if (argc == 2 && !strcmp(argv[1], "0")) {
		reset_counters();	
	} else {
		fprintf(stderr, "You must pass no arguments or exactly one argument with value \"0\"\n");
		exit(1);
	}
	return 0;
}

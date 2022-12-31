#include "fw_user.h"
#include "user_print.h"
#include "user_parse.h"


// copies the active rule table of the firewall to our local rule table
void get_rule_table() {
	int fd;
	if ((fd = open("/sys/class/" CLASS_NAME "/" DEVICE_NAME_RULES "/rules", O_RDONLY)) == -1) {
		perror("open");
		exit(1);
	}

	if (read(fd, rule_table, RULE_TABLE_SIZE) < RULE_TABLE_SIZE) {
		close(fd);
		perror("read");
		exit(1);
	}

	close(fd);
}


void show_rules() {
	int i = 0;
	get_rule_table();
	// while the rule name isn't an empty string, because an empty name means we've reached the end
	while (rule_table[i].rule_name[0] != 0 && i < MAX_RULES) {
		print_rule(&rule_table[i]); // prints the i-th rule
		++i;
	}
}


void load_rules(char* path_to_rules_file) {
	parse_rules_file(path_to_rules_file); // parsing the rules file into our rule_table
	
	int fd;
	if ((fd = open("/sys/class/" CLASS_NAME "/" DEVICE_NAME_RULES "/rules", O_WRONLY)) == -1) {
		perror("open");
		exit(1);
	}

	if (write(fd, rule_table, num_rules * sizeof(rule_t)) != num_rules * sizeof(rule_t)) { // sends the rule table to the firewall module
		close(fd);
		perror("write");
		exit(1);
	}

	close(fd);
}


// reads the logs from the firewall module and prints each row as desired
void show_log() {
	log_row_t log_row;
	int i = 0, bytes_read, fd;

	if ((fd = open("/dev/" DEVICE_NAME_LOG, O_RDONLY)) == -1) {
		perror("open");
		exit(1);
	}

	printf("timestamp\t\t\tsrc_ip\t\t\tdst_ip\t\t\tsrc_port\tdst_port\tprotocol\taction\treason\t\t\tcount\n"); // the headline
	while (bytes_read = read(fd, &log_row, sizeof(log_row_t))) {
		if (bytes_read != sizeof(log_row_t)) { // we read a single log row every time
			close(fd);
			perror("read");
			exit(1);
		}
		print_log_row(&log_row);
	}
	close(fd);
}


// notify the firewall module to clear the logs by sending an arbitrary byte (in this case, "1")
void clear_log() {
	FILE *f;
	if (!(f = fopen("/sys/class/" CLASS_NAME "/" DEVICE_NAME_LOG "/reset", "w"))) {
		perror("fopen");
		exit(1);
	}

	if (fprintf(f, "%u\n", 1) < 0) {
		fclose(f);
		perror("fprintf");
		exit(1);
	}

	fclose(f);
}


// copies the current connection table of the firewall to our local connection table
void get_conn_tab() {
	int fd;
	if ((fd = open("/sys/class/" CLASS_NAME "/" DEVICE_NAME_CONN_TAB "/conns", O_RDONLY)) == -1) {
		perror("open");
		exit(1);
	}

	if ((num_conn_entries = read(fd, conn_tab, PAGE_SIZE)) == -1) {
		close(fd);
		perror("read");
		exit(1);
	}
	
	num_conn_entries = num_conn_entries / sizeof(conn_entry_t);
	close(fd);
}


void show_conns() {
	int i = 0;
	get_conn_tab();
	printf("src_ip\t\tsrc_port\tdst_ip\t\tdst_port\tstate\t\ttype\tclient_ip\tclient_port\tserver_ip\tserver_port\tforged_client_port\trandom_ftp_data_port\n"); // the headline
	for (i = 0; i < num_conn_entries; i++) {
		print_conn_entry(&conn_tab[i]); // prints the i-th conn_entry
	}
}


int main(int argc, char *argv[]) {
	memset(rule_table, 0, RULE_TABLE_SIZE);

	if (argc == 2) {
		if (!strcmp(argv[1], "show_rules")) {
			show_rules();
			return 0;
		} else if (!strcmp(argv[1], "show_log")) {
			show_log();
			return 0;
		} else if (!strcmp(argv[1], "clear_log")) {
			clear_log();
			return 0;
		} else if (!strcmp(argv[1], "show_conns")) {
			show_conns();
			return 0;
		} 
	} else if (argc == 3 && !strcmp(argv[1], "load_rules")) { // "load_rules" is the only command which needs another argument
		load_rules(argv[2]);
		return 0;
	}
	print_error_message_and_exit(
		"You must pass one of the following:\nshow_rules\nload_rules <path_to_rules_file>\nshow_log\nclear_log\nshow_conns"
		);
	return 0;
}

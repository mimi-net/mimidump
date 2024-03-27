#define APP_NAME "Mimidump"
#define APP_DESC "Sniffer for the miminet using libpcap"
#define APP_COPYRIGHT "Copyright (c) 2024 Ilya Zelenechuk"
#define APP_DISCLAIMER "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <arpa/inet.h>
#include <bsd/string.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <pthread.h>
#include <signal.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* Max len interface name */
#define IFSZ 16

/* Max len of filename for the packet store */
#define PCAP_FILENAME_SIZE 512

/* Max number of packet to be captured */
#define MAX_PACKET_CAPTURE 100

/* Max lenght of packet filter string */
#define MAX_FILTER_STRING 512

/* Define thread info structure */
struct thread_info
{
	/* Arg for thread_start() */
	pthread_t thread_id; /* ID returned from pthread_create() */
	int thread_num;      /* thread number */
	pcap_t *handler;     /* pcap handler */
	pcap_dumper_t *pd;   /* pcap dump to file handler */
	int num_packets;     /* max number of packets to be captures */
};

struct thread_info *tinfo;

/*
 * print help text
 */
void print_app_usage(void)
{
	printf("Usage: %s interface inout_pcap_file out_pcap_file <filter>\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface		Listen on <interface> for packets.\n");
	printf("    inout_pcap_file	Where to write IN/OUT raw packets.\n");
	printf("    out_pcap_file	Where to write only OUT raw packets.\n");
	printf("    <filter>		Tcpdump like filter string.\n");
	printf("\n");
}

/* Signal handler */
void sig_handler(int signo)
{
	if (signo == SIGINT) {
		printf("Got SIGINT. Call pcap_breakloop.\n");
		pcap_breakloop(tinfo[0].handler);
		pcap_breakloop(tinfo[1].handler);
	}
}

static void *thread_handle_inout_packets(void *arg)
{
	struct thread_info *tinfo = arg;

	pcap_loop(tinfo->handler, tinfo->num_packets, &pcap_dump, (u_char *)tinfo->pd);
	return 0;
}

static void *thread_handle_out_packets(void *arg)
{
	struct thread_info *tinfo = arg;

	pcap_loop(tinfo->handler, tinfo->num_packets, &pcap_dump, (u_char *)tinfo->pd);
	return 0;
}

int main(int argc, char **argv)
{
	char dev[IFSZ];
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_string[MAX_FILTER_STRING];
	pcap_t *handle_inout;
	pcap_t *handle_out;
	pcap_dumper_t *pd_inout; /* pointer to the dump file */
	pcap_dumper_t *pd_out;   /* pointer to the dump file */

	struct bpf_program bprog; /* compiled bpf filter program */

	char pcap_inout_filename[PCAP_FILENAME_SIZE];
	char pcap_out_filename[PCAP_FILENAME_SIZE];

	pthread_attr_t attr;
	size_t num_threads = 2;
	int s;
	void *res;

	/* Set SIGINT handler */
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "Can't catch SIGINT\n");
		exit(EXIT_FAILURE);
	}

	/* check for capture device name on command-line */
	if (argc < 4) {
		fprintf(stderr, "Invalid command-line options count\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}

	if (strlcpy(dev, argv[1], sizeof(dev)) >= sizeof(dev)) {
		fprintf(stderr, "Invalid interface name.\n");
		exit(EXIT_FAILURE);
	}

	filter_string[0] = '\0';

	/* Read filters */
	/* Be sure you have not less 4 arguments */
	for (int i = 4; i < argc; i++) {

		unsigned int pos = strlen(filter_string);
		size_t len = strlen(argv[i]);

		/* Do we have a room for another one argument? */
		if ((MAX_FILTER_STRING - len - pos) <= 0) {
			fprintf(stderr, "Filter string is too long. Must be less than 512 symbols\n");
			exit(EXIT_FAILURE);
		}

		// Copy a whitespace
		if (pos > 0) {
			memcpy(&filter_string[pos], " \0", 2);
			pos++;
		}

		memcpy(&filter_string[pos], argv[i], len);
		filter_string[pos + len] = '\0';
	}

	/* Making pcap filenames */
	if (strlcpy(pcap_inout_filename, argv[2], sizeof(pcap_inout_filename)) >= sizeof(pcap_inout_filename)) {
		fprintf(stderr, "Invalid inout filename len.\n");
		exit(EXIT_FAILURE);
	}

	if (strlcpy(pcap_out_filename, argv[3], sizeof(pcap_out_filename)) >= sizeof(pcap_out_filename)) {
		fprintf(stderr, "Invalid out filename len.\n");
		exit(EXIT_FAILURE);
	}

	/* open capture device */
	handle_inout = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle_inout == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	handle_out = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle_out == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* set direction IN */
	pcap_setdirection(handle_inout, PCAP_D_INOUT);
	pcap_setdirection(handle_out, PCAP_D_OUT);

	/* Set filters */
	if (pcap_compile(handle_inout, &bprog, filter_string, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		fprintf(stderr, "Error compiling IN/OUT bpf filter on\n");
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle_inout, &bprog) < 0) {
		fprintf(stderr, "Error installing IN/OUT bpf filter\n");
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle_out, &bprog, filter_string, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		fprintf(stderr, "Error compiling OUT bpf filter on\n");
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle_out, &bprog) < 0) {
		fprintf(stderr, "Error installing OUT bpf filter\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Open dump device for writing packet capture data.
	 */
	if ((pd_inout = pcap_dump_open(handle_inout, pcap_inout_filename)) == NULL) {
		fprintf(
		  stderr, "Error opening savefile \"%s\" for writing: %s\n", pcap_inout_filename, pcap_geterr(handle_inout));
		exit(EXIT_FAILURE);
	}

	if ((pd_out = pcap_dump_open(handle_out, pcap_out_filename)) == NULL) {
		fprintf(stderr, "Error opening savefile \"%s\" for writing: %s\n", pcap_out_filename, pcap_geterr(handle_out));
		exit(EXIT_FAILURE);
	}

	/* Init pthread attributes */
	s = pthread_attr_init(&attr);
	if (s != 0) {
		fprintf(stderr, "pthread_attr_init error\n");
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for pthread_create() arguments. */
	tinfo = calloc(num_threads, sizeof(*tinfo));
	if (tinfo == NULL) {
		fprintf(stderr, "Can't alloca memory (calloc) for tinfo structure");
		exit(EXIT_FAILURE);
	}

	/* Start threads */
	tinfo[0].thread_num = 1;
	tinfo[0].handler = handle_inout;
	tinfo[0].num_packets = MAX_PACKET_CAPTURE;
	tinfo[0].pd = pd_inout;
	s = pthread_create(&tinfo[0].thread_id, &attr, &thread_handle_inout_packets, &tinfo[0]);

	if (s != 0) {
		fprintf(stderr, "Can't create thread_handle_inout_packets\n");
		exit(EXIT_FAILURE);
	}

	tinfo[1].thread_num = 2;
	tinfo[1].handler = handle_out;
	tinfo[1].num_packets = MAX_PACKET_CAPTURE;
	tinfo[1].pd = pd_out;
	s = pthread_create(&tinfo[1].thread_id, &attr, &thread_handle_out_packets, &tinfo[1]);

	if (s != 0) {
		fprintf(stderr, "Can't create thread_handle_out_packets\n");
		exit(EXIT_FAILURE);
	}

	/* Now join with each thread, and display its returned value. */

	s = pthread_join(tinfo[0].thread_id, &res);
	if (s != 0) {
		fprintf(stderr, "Error while join the thread 1\n");
		exit(EXIT_FAILURE);
	}

	free(res);

	s = pthread_join(tinfo[1].thread_id, &res);
	if (s != 0) {
		fprintf(stderr, "Error while join the thread 2\n");
		exit(EXIT_FAILURE);
	}

	free(res);

	pcap_dump_close(pd_inout);
	pcap_dump_close(pd_out);
	pcap_close(handle_inout);
	pcap_close(handle_out);
	return 0;
}

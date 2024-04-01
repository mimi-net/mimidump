#define APP_NAME "Mimidump"
#define APP_DESC "Sniffer for the miminet using libpcap"
#define APP_COPYRIGHT "Copyright (c) 2024 Ilya Zelenechuk"
#define APP_DISCLAIMER "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <bsd/string.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <sys/poll.h>

/* Max len of filename for the packet store */
#define PCAP_FILENAME_SIZE 512

/* Max number of packet to be captured */
#define MAX_PACKET_CAPTURE 100

/* Max lenght of packet filter string */
#define MAX_FILTER_STRING 512

/* handle settings*/

/* default snap length (maximum bytes per packet to capture) */
#define HANDLE_SNAP_LEN 1518

/* if is non-zero, promiscuous mode will be set */
#define HANDLE_PROMISC 1

/* delay to accumulate packets before being delivered  */
#define HANDLE_BUFFER_TIMEOUT 1000

/* timeout to wait interface up in sec */
#define IFUP_TIMEOUT_S 1

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

static void *thread_handle_packets(void *arg)
{
	struct thread_info *tinfo = arg;

	pcap_loop(tinfo->handler, tinfo->num_packets, &pcap_dump, (u_char *)tinfo->pd);
	return 0;
}

static int configure_pcap_handle(pcap_t *handle)
{
	return pcap_set_promisc(handle, HANDLE_PROMISC) || pcap_set_snaplen(handle, HANDLE_SNAP_LEN) ||
	       pcap_set_timeout(handle, HANDLE_BUFFER_TIMEOUT);
}

static int open_netlink_socket(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		fprintf(stderr, "Cannot open netlink socket\n");
		return -1;
	}

	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;
	sa.nl_pid = getpid();
	if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa))) {
		fprintf(stderr, "Cannot bind netlink socket\n");
		close(fd);
		return -1;
	}
	return fd;
}

static int read_netlink_msg_ifup(int fd, int ifindex)
{
	struct nlmsghdr buf[8192 / sizeof(struct nlmsghdr)];
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	struct sockaddr_nl sa;
	struct msghdr msg = { .msg_name = &sa,
		                  .msg_namelen = sizeof(sa),
		                  .msg_iov = &iov,
		                  .msg_iovlen = 1,
		                  .msg_control = NULL,
		                  .msg_controllen = 0,
		                  .msg_flags = 0 };
	ssize_t len = recvmsg(fd, &msg, 0);
	if (len < 0) {
		fprintf(stderr, "Cannot receive netlink message\n");
		return -1;
	}
	if (msg.msg_namelen != sizeof(sa)) {
		fprintf(stderr, "Invalid address length in netlink message\n");
		return -1;
	}
	for (struct nlmsghdr *nh = buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_type == NLMSG_DONE) {
			return 0;
		}
		if (nh->nlmsg_type == NLMSG_ERROR) {
			fprintf(stderr, "\n");
			return -1;
		}
		if (nh->nlmsg_type != RTM_NEWLINK) {
			continue;
		}
		struct ifinfomsg *ifinfo = NLMSG_DATA(nh);
		if (ifinfo->ifi_index != ifindex) {
			continue;
		}
		return ((int)ifinfo->ifi_flags & IFF_UP);
	}
	return 0;
}

static int wait_interface_up(const char *dev)
{
	printf("Waiting interface %s UP\n", dev);
	int ifindex = (int)if_nametoindex(dev);
	if (!ifindex) {
		fprintf(stderr, "Cannot get interface index by name\n");
		return -1;
	}
	int fd = open_netlink_socket();
	if (fd < 0) {
		return -1;
	}

	struct pollfd pfds[1] = { { .fd = fd, .events = POLLIN } };
	for (int i = 0; i < 100; ++i) {
		int prc = poll(pfds, 1, IFUP_TIMEOUT_S * 1000);
		int ifup;
		switch (prc) {
			case 0:
				continue;
			case -1:
				fprintf(stderr, "Cannot poll netlink socket\n");
				close(fd);
				return -1;
			default:
				ifup = read_netlink_msg_ifup(fd, ifindex);
				if (ifup < 0) {
					close(fd);
					return -1;
				} else if (ifup) {
					close(fd);
					return 1;
				}
				break;
		}
	}
	close(fd);
	return 0;
}

static pcap_t *create_pcap_handle_waiting_ifup(const char *dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int wait = 1;
	pcap_t *handle = NULL;
	while (!handle) {
		handle = pcap_create(dev, errbuf);
		if (!handle) {
			fprintf(stderr, "%s", errbuf);
			return NULL;
		}
		if (configure_pcap_handle(handle) == PCAP_ERROR_ACTIVATED) {
			fprintf(stderr, "Handle for interface %s has been already activated\n", dev);
			pcap_close(handle);
			return NULL;
		}
		int rc_activate = pcap_activate(handle);
		if (wait && rc_activate == PCAP_ERROR_IFACE_NOT_UP) {
			pcap_close(handle);
			handle = NULL;
			if (!wait_interface_up(dev)) {
				fprintf(stderr, "Interface %s is DOWN\n", dev);
				return NULL;
			}
			wait = 0;
			continue;
		} else if (rc_activate < 0) {
			pcap_perror(handle, "Cannot create pcap handle");
			pcap_close(handle);
			return NULL;
		} else if (rc_activate > 0) {
			pcap_perror(handle, "Warning");
		}
	}
	return handle;
}

int main(int argc, char **argv)
{
	char dev[IF_NAMESIZE];
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
		return EXIT_FAILURE;
	}

	/* check for capture device name on command-line */
	if (argc < 4) {
		fprintf(stderr, "Invalid command-line options count\n\n");
		print_app_usage();
		return EXIT_FAILURE;
	}

	if (strlcpy(dev, argv[1], sizeof(dev)) >= sizeof(dev)) {
		fprintf(stderr, "Invalid interface name.\n");
		return EXIT_FAILURE;
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
			return EXIT_FAILURE;
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
		return EXIT_FAILURE;
	}

	if (strlcpy(pcap_out_filename, argv[3], sizeof(pcap_out_filename)) >= sizeof(pcap_out_filename)) {
		fprintf(stderr, "Invalid out filename len.\n");
		return EXIT_FAILURE;
	}

#ifdef PCAP_AVAILABLE_1_10
	// Initialize pcap library
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "%.*s\n", PCAP_ERRBUF_SIZE, errbuf);
		return EXIT_FAILURE;
	}
#endif

	handle_inout = create_pcap_handle_waiting_ifup(dev);
	if (!handle_inout) {
		return EXIT_FAILURE;
	}
	handle_out = create_pcap_handle_waiting_ifup(dev);
	if (!handle_out) {
		return EXIT_FAILURE;
	}
	printf("Pcap handles are successfully created\n");
	pcap_setdirection(handle_inout, PCAP_D_INOUT);
	pcap_setdirection(handle_out, PCAP_D_OUT);
	/* Set filters */
	if (pcap_compile(handle_inout, &bprog, filter_string, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		pcap_perror(handle_inout, "Error compiling IN/OUT bpf filter on");
		return EXIT_FAILURE;
	}
	if (pcap_setfilter(handle_inout, &bprog) < 0) {
		pcap_perror(handle_inout, "Error installing IN/OUT bpf filter");
		return EXIT_FAILURE;
	}
	if (pcap_compile(handle_out, &bprog, filter_string, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		pcap_perror(handle_out, "Error compiling OUT bpf filter on");
		return EXIT_FAILURE;
	}
	if (pcap_setfilter(handle_out, &bprog) < 0) {
		pcap_perror(handle_out, "Error installing OUT bpf filter");
		return EXIT_FAILURE;
	}

	/*
	 * Open dump device for writing packet capture data.
	 */
	if ((pd_inout = pcap_dump_open(handle_inout, pcap_inout_filename)) == NULL) {
		fprintf(
		  stderr, "Error opening savefile \"%s\" for writing: %s\n", pcap_inout_filename, pcap_geterr(handle_inout));
		return EXIT_FAILURE;
	}

	if ((pd_out = pcap_dump_open(handle_out, pcap_out_filename)) == NULL) {
		fprintf(stderr, "Error opening savefile \"%s\" for writing: %s\n", pcap_out_filename, pcap_geterr(handle_out));
		return EXIT_FAILURE;
	}

	/* Init pthread attributes */
	s = pthread_attr_init(&attr);
	if (s != 0) {
		fprintf(stderr, "pthread_attr_init error\n");
		return EXIT_FAILURE;
	}

	/* Allocate memory for pthread_create() arguments. */
	tinfo = calloc(num_threads, sizeof(*tinfo));
	if (tinfo == NULL) {
		fprintf(stderr, "Can't alloca memory (calloc) for tinfo structure");
		return EXIT_FAILURE;
	}

	/* Start threads */
	tinfo[0].thread_num = 1;
	tinfo[0].handler = handle_inout;
	tinfo[0].num_packets = MAX_PACKET_CAPTURE;
	tinfo[0].pd = pd_inout;
	s = pthread_create(&tinfo[0].thread_id, &attr, &thread_handle_packets, &tinfo[0]);

	if (s != 0) {
		fprintf(stderr, "Can't create thread_handle_inout_packets\n");
		return EXIT_FAILURE;
	}

	tinfo[1].thread_num = 2;
	tinfo[1].handler = handle_out;
	tinfo[1].num_packets = MAX_PACKET_CAPTURE;
	tinfo[1].pd = pd_out;
	s = pthread_create(&tinfo[1].thread_id, &attr, &thread_handle_packets, &tinfo[1]);

	if (s != 0) {
		fprintf(stderr, "Can't create thread_handle_out_packets\n");
		return EXIT_FAILURE;
	}

	/* Now join with each thread, and display its returned value. */

	s = pthread_join(tinfo[0].thread_id, &res);
	if (s != 0) {
		fprintf(stderr, "Error while join the thread 1\n");
		return EXIT_FAILURE;
	}

	free(res);

	s = pthread_join(tinfo[1].thread_id, &res);
	if (s != 0) {
		fprintf(stderr, "Error while join the thread 2\n");
		return EXIT_FAILURE;
	}

	free(res);

	pcap_dump_close(pd_inout);
	pcap_dump_close(pd_out);
	pcap_close(handle_inout);
	pcap_close(handle_out);
	return 0;
}

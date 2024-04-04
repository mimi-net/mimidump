#define APP_NAME "Mimidump"
#define APP_DESC "Sniffer for the miminet using libpcap"
#define APP_COPYRIGHT "Copyright (c) 2024 Ilya Zelenechuk"
#define APP_DISCLAIMER "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."
#define APP_AUTHOR "Ilya Zelenchuk, Vladimir Kutuev"

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
#include <sys/timerfd.h>

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
#define IFUP_TIMEOUT_S 100

/**
 * @brief Structure describing captor based on pcap.
 * @struct
 */
struct captor
{
	pcap_t *handle;           /* live capture handle */
	pcap_dumper_t *dump;      /* pcap dump file */
	struct bpf_program bprog; /* compiled packages filter */
};

/**
 * @brief Thread info structure. An argument for pthread_create(...).
 * @struct
 */
struct thread_info
{
	struct captor captor; /* captor */
	pthread_t thread_id;  /* ID returned from pthread_create() */
	int thread_num;       /* thread number */
	int num_packets;      /* max number of packets to be captures */
};

#define NUM_THREADS 2
static const size_t num_threads = NUM_THREADS;
static struct thread_info tinfo[NUM_THREADS];

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
		pcap_breakloop(tinfo[0].captor.handle);
		pcap_breakloop(tinfo[1].captor.handle);
	}
}

static void *thread_handle_packets(void *arg)
{
	struct thread_info *local_tinfo = arg;

	pcap_loop(local_tinfo->captor.handle, local_tinfo->num_packets, &pcap_dump, (u_char *)local_tinfo->captor.dump);
	return 0;
}

/**
 * @internal
 * @brief Configure created pcap capture @p handle with
 *        promisc mode, snapshot length and buffer timeout before activation.
 * @param[in, out] handle
 * @return @p 0 on success and @p PCAP_ERROR_ACTIVATED if @p handle has been activated.
 */
static int configure_pcap_handle(pcap_t *handle)
{
	return pcap_set_promisc(handle, HANDLE_PROMISC) || pcap_set_snaplen(handle, HANDLE_SNAP_LEN) ||
	       pcap_set_timeout(handle, HANDLE_BUFFER_TIMEOUT);
}

/**
 * @internal
 * @brief Create and bind netlink socket.
 * @return socket file descriptor on success and @p -1 on failure.
 */
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

/**
 * @internal
 * @brief Read netlink message from @p fd socket and check interface with index @p ifindex is up.
 * @param[in] fd netlink socket
 * @param[in] ifindex network interface name
 * @return @p -1 on error, positive value if interface become UP and @p 0 else.
 */
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

/**
 * @internal
 * @brief Wait until interface @p dev become UP or some timeout expired.
 * @param[in] dev interface name
 * @return @p -1 on error, positive value if interface become UP and @p 0 else.
 */
static int wait_interface_up(const char *dev)
{
	printf("Waiting interface %s UP\n", dev);
	int ifindex = (int)if_nametoindex(dev);
	if (!ifindex) {
		fprintf(stderr, "Cannot get interface index by name\n");
		return -1;
	}

	/* Configure netlink socket and timerfd */
	int netlinkfd = open_netlink_socket();
	if (netlinkfd < 0) {
		return -1;
	}
	int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timerfd < 0) {
		fprintf(stderr, "Cannot open timerfd socket\n");
		close(netlinkfd);
		return -1;
	}
	struct itimerspec timerspec = { .it_interval = { 0, 0 }, { IFUP_TIMEOUT_S, 0 } };
	timerfd_settime(timerfd, 0, &timerspec, NULL);

	/* Poll netlinkfd and timerfd until interface UP or timeout expired */
	struct pollfd pfds[] = { { .fd = netlinkfd, .events = POLLIN }, { .fd = timerfd, .events = POLLIN } };
	struct pollfd *netlinkpfd = pfds, *timerpfd = pfds + 1;
	int ifup = 0;

	for (;;) {
		int prc = poll(pfds, sizeof(pfds) / sizeof(pfds[0]), IFUP_TIMEOUT_S * 1000);
		if (!prc) {
			continue;
		}
		if (prc < 0) {
			fprintf(stderr, "Cannot poll netlink socket\n");
			ifup = -1;
			break;
		}
		if (timerpfd->revents & POLLIN) {
			/* Timeout expired */
			timerpfd->revents = 0;
			ifup = 0;
			break;
		}
		if (netlinkpfd->revents & POLLIN) {
			netlinkpfd->revents = 0;
			ifup = read_netlink_msg_ifup(netlinkfd, ifindex);
			if (ifup) {
				/* Interface UP or error */
				break;
			}
		}
	}
	close(netlinkfd);
	close(timerfd);
	return ifup;
}

/**
 * @internal
 * @brief Create, configure and activate pcap live capture handle for @p dev interface.
 * @param[in] dev interface name
 * @return Activated handle on success and @p NULL on failure.
 */
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

/**
 * @internal
 * @brief Initialize captor for interface @p dev.
 * @param[in, out] cptr pointer to captor
 * @param[in] dev name of the interface to be captured
 * @param[in] direction direction that packets will be captured
 * @param[in] filter_string string for specifying the captor filter program
 * @param[in] output_filename filename to save pcap dump
 * @return @p 0 on success and nonzero value on failure.
 */
int init_captor(struct captor *cptr,
                const char *dev,
                pcap_direction_t direction,
                const char *filter_string,
                const char *output_filename)
{
	char *direction_str = direction == PCAP_D_INOUT ? "IN/OUT" : "OUT";
	cptr->handle = create_pcap_handle_waiting_ifup(dev);
	if (!cptr->handle) {
		return 1;
	}

	printf("Pcap handle for %s captor successfully created\n", direction_str);
	pcap_setdirection(cptr->handle, direction);

	/* Set filters */
	if (pcap_compile(cptr->handle, &cptr->bprog, filter_string, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		fprintf(stderr, "Error compiling %s bpf filter on: %s", direction_str, pcap_geterr(cptr->handle));
		return 1;
	}
	if (pcap_setfilter(cptr->handle, &cptr->bprog) < 0) {
		fprintf(stderr, "Error installing %s bpf filter on: %s", direction_str, pcap_geterr(cptr->handle));
		return 1;
	}
	/*
	 * Open dump device for writing packet capture data.
	 */
	if ((cptr->dump = pcap_dump_open(cptr->handle, output_filename)) == NULL) {
		fprintf(stderr, "Error opening savefile \"%s\" for writing: %s\n", output_filename, pcap_geterr(cptr->handle));
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	/* check for capture device name on command-line */
	if (argc < 4) {
		fprintf(stderr, "Invalid command-line options count\n\n");
		print_app_usage();
		return EXIT_FAILURE;
	}

	char dev[IF_NAMESIZE];
	if (strlcpy(dev, argv[1], sizeof(dev)) >= sizeof(dev)) {
		fprintf(stderr, "Invalid interface name.\n");
		return EXIT_FAILURE;
	}

	char filter_string[MAX_FILTER_STRING];
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

#ifdef PCAP_AVAILABLE_1_10
	// Initialize pcap library
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "%.*s\n", PCAP_ERRBUF_SIZE, errbuf);
		return EXIT_FAILURE;
	}
#endif

	/* Init pthread attributes */
	pthread_attr_t attr;
	int thrc = pthread_attr_init(&attr);
	if (thrc != 0) {
		fprintf(stderr, "pthread_attr_init error\n");
		return EXIT_FAILURE;
	}

	/* Configure threads */
	tinfo[0].thread_num = 1;
	tinfo[0].num_packets = MAX_PACKET_CAPTURE;
	if (init_captor(&tinfo[0].captor, dev, PCAP_D_INOUT, filter_string, argv[2])) {
		return EXIT_FAILURE;
	}
	tinfo[1].thread_num = 2;
	if (init_captor(&tinfo[1].captor, dev, PCAP_D_OUT, filter_string, argv[3])) {
		return EXIT_FAILURE;
	}
	tinfo[1].num_packets = MAX_PACKET_CAPTURE;

	/* Set SIGINT handler */
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "Can't catch SIGINT\n");
		return EXIT_FAILURE;
	}
	/* Start threads */
	for (size_t i = 0; i < num_threads; ++i) {
		thrc = pthread_create(&tinfo[i].thread_id, &attr, &thread_handle_packets, &tinfo[i]);

		if (thrc != 0) {
			fprintf(stderr, "Can't create thread_handle_out_packets\n");
			return EXIT_FAILURE;
		}
	}

	/* Now join with each thread, and display its returned value. */
	for (size_t i = 0; i < num_threads; ++i) {
		void *res;
		thrc = pthread_join(tinfo[i].thread_id, &res);
		if (thrc != 0) {
			fprintf(stderr, "Error while join the thread 1\n");
			return EXIT_FAILURE;
		}

		free(res);
	}

	for (size_t i = 0; i < num_threads; ++i) {
		pcap_dump_close(tinfo[i].captor.dump);
		pcap_close(tinfo[i].captor.handle);
	}

	return EXIT_SUCCESS;
}

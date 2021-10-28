/*
 * Copyright (c) 2008-2021 Andreas Lundin <lunde@dreamhosted.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/time.h>

#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <pcap.h>

#include "ifpstat.h"

#define VERSION "1.0"

/* if strlcat isn't defined include our own copy */
#ifndef strlcat
size_t	strlcat(char*, const char *, size_t);
#endif

static char 	*concat_argv(char * const *, const char *);
static int	 init_timer(const int, sig_t);
static void	 packet_catch(u_char *, const struct pcap_pkthdr *,
    const u_char *);
static void	 usage(void);
static void	 version(void);

/* global command line arguments */
int 		 FLG_CSV, FLG_BWDIVIDER, FLG_TIME, FLG_PPSDIVIDER, FLG_DROPS;
int		 FLG_TIMESTAMP;
int64_t		 FLG_BWMULTIPLIER;
long		 FLG_CNT;

int64_t 	 cntBytes;	/* counter for matched bytes */
int64_t 	 cntPackets;	/* counter for matched packets  */
time_t		 periodStart;	/* timestamp for start of measurement period */
pcap_t		*pcap_p;	/* pcap pointer */

/* init_timer starts a timer that trigger func on each interval */
static int
init_timer(const int interval, sig_t func)
{
	struct itimerval timer;

	signal(SIGALRM, func);

	/* time to next first SIGALRM */
	timer.it_value.tv_sec = interval;
	timer.it_value.tv_usec = 0;
	/* interval for following SIGALRM */
	timer.it_interval.tv_sec = interval;
	timer.it_interval.tv_usec = 0;

	return setitimer(ITIMER_REAL, &timer, NULL);
}

/*
 * ifpstat is a command line tool to report bandwidth and packet rates
 * of a network interface while using libpcap to filter which network
 * traffic is reported.
 */
int
main(int argc, char *argv[])
{
	/* by default report both incoming and outgoing traffic */
	pcap_direction_t	direction = PCAP_D_INOUT;

	char 	 headerBWUnit = 'B'; 		/* default is B as in Byte */
	char 	*headerBWPrefix = "Ki"; 	/* default is KiBps */
	char 	*headerPacketPrefix = ""; 	/* default is no unit prefix */
	char 	*dev = NULL; 			/* device name */
	char	*endp;
	char 	*pcapFilter = NULL;		/* pcap filter */
	int 	 ch; 				/* getopt return value */
	int 	 err;				/* return values */
	int	 header;			/* print header */
	int	 promisc;			/* promiscuous mode */

	/* reset global counters */
	cntBytes = 0;
	cntPackets = 0;

	FLG_BWDIVIDER = 1024;	/* default is Ki unit divider */
	FLG_BWMULTIPLIER = 1; 	/* bytes/bits multiplier */
	FLG_CNT = 0;        	/* how many announcements to make */
	FLG_CSV = 0;        	/* print output as csv */
	FLG_DROPS = 0;		/* 0 = don't print drops
				 * 1 = print drops */
	FLG_TIME = 1;       	/* 1 second between output */
	FLG_TIMESTAMP = 0;  	/* 0 = don't print time stamp
				 * 1 = print time stamp */
	FLG_PPSDIVIDER = 1;	/* unit divider for packets */
	header = 1;     	/* 0 = don't print header
				 * 1 = print header */
	promisc = 0;		/* 0 = don't set device to promiscuous mode
				 * 1 = set device to promiscuous mode  */

	while ((ch = getopt(argc, argv, "BbCc:Dd:f:hi:KMmnptvw:")) != -1) {
		switch (ch) {
		case 'B':
			/* don't report in kilo bit/bytes */
			FLG_BWDIVIDER = 1;
			headerBWPrefix = "";
			break;
		case 'b':
			/* bits insted of bytes */
			FLG_BWMULTIPLIER = 8;
			headerBWUnit = 'b';
			break;
		case 'C':
			/* print as CSV */
			FLG_CSV = 1;
			break;
		case 'c':
			/* exit after FLG_CNT announcements */
			FLG_CNT = strtol(optarg, &endp, 0);
			if (optarg[0] == '\0' || endp[0] != '\0' ||
			    FLG_CNT == LONG_MAX) {
				fprintf(stderr,
				    "Error: invalid report count\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'D':
			/* print drops */
			FLG_DROPS = 1;
			break;
		case 'd':
			/* set capture direction */
			if (strcmp(optarg, "in") == 0)
				direction = PCAP_D_IN;
			else if (strcmp(optarg, "out") == 0)
				direction = PCAP_D_OUT;
			else if (strcmp(optarg, "any") == 0)
				direction = PCAP_D_INOUT;
			else
				usage();
			break;
		case 'f':
			/* pcap filter string */
			pcapFilter = optarg;
			break;
		case 'h':
			/* print help and exit */
			usage();
			break;
		case 'i':
			/* set device */
			dev = optarg;
			break;
		case 'K':
			/* kilo for pps */
			FLG_PPSDIVIDER = 1000;
			headerPacketPrefix = "k";
			break;
		case 'M':
			/* mega for pps */
			FLG_PPSDIVIDER = 1000 * 1000;
			headerPacketPrefix = "M";
			break;
		case 'm':
			/* mega */
			FLG_BWDIVIDER = 1024 * 1024;
			headerBWPrefix = "Mi";
			break;
		case 'n':
			/* don't print the header */
			header = 0;
			break;
		case 'p':
			/* enable promiscuous mode */
			promisc = 1;
			break;
		case 't':
			/* print timestamp */
			FLG_TIMESTAMP = 1;
			break;
		case 'v':
			/* print version and exit */
			version();
			break;
		case 'w':
			/* wait between the announcements */
			FLG_TIME = atoi(optarg);
			break;
		case '?':
		default:
			/* print help and exit */
			usage();
			break;
		}
	}

	if (FLG_CNT < 0) {
		fprintf(stderr,
		    "Error: Report count should be an integer of value 1 or larger\n");
		exit(EXIT_FAILURE);
	}

	if (FLG_TIME < 0) {
		fprintf(stderr,
		    "Error: Wait should be an integer of value 0 or larger\n");
		exit(EXIT_FAILURE);
	}

	pcapFilter = concat_argv(&argv[optind], " ");

	/* if we're reporting in bits change the divider, because reasons */
	if (FLG_BWMULTIPLIER == 8) {
		if (FLG_BWDIVIDER == 1024) {
			headerBWPrefix = "k";
			FLG_BWDIVIDER = 1000;
		}
		if (FLG_BWDIVIDER == 1024 * 1024) {
			headerBWPrefix = "M";
			FLG_BWDIVIDER = 1000 * 1000;
		}
	}

	pcap_p = net_init_pcap(dev, pcapFilter, direction, promisc);
	if (pcap_p == NULL) {
		exit(EXIT_FAILURE);
	}

	if (FLG_TIME == 0) {
		periodStart = time(NULL);
		signal(SIGUSR1, print_stats);
	} else {
		err = init_timer(FLG_TIME, print_stats);
		if (err != 0) {
			fprintf(stderr, "Error: Failed to set timer\n");
			exit(EXIT_FAILURE);
		}
	}

	/* print header */
	if (header) {
		print_header(headerBWPrefix, headerBWUnit, headerPacketPrefix);
	}

	err = pcap_loop(pcap_p, -1, packet_catch, NULL);
	if (err == PCAP_ERROR) {
		fprintf(stderr, "Error: pcap_loop: %s\n", pcap_geterr(pcap_p));
		pcap_close(pcap_p);
		exit(EXIT_FAILURE);
	}

	pcap_close(pcap_p);

	return 0;
}

/* packet_catch is the callback function for each captured packet */
static void
packet_catch(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{
	/* increase global counters */
	cntPackets++;
	cntBytes += header->len;
}

/* usage prints command line help to stderr and exit */
static void
usage(void)
{
	fprintf(stderr,
	    "usage: "
	    "ifpstat\t[-BbCDhKMmnptv] [-c count] [-d in|out|any]"
	    " [-i interface]\n\t[-w delay] [expression]\n");
	exit(EXIT_FAILURE);
}

/* version prints version and exit */
static void
version(void)
{
	fprintf(stderr, "ifpstat %s\n", VERSION);
	exit(EXIT_SUCCESS);
}

/*
 * concat_argv concatenates an array of strings (argv) into one string
 * separated by sep and returns the resulting string. last element of
 * the array must be null. returns null on error.
 */
static char *
concat_argv(char * const *argv, const char *sep)
{
	size_t	 i, len;
	char	*buf;

	if (argv == NULL || argv[0] == NULL)
		return NULL;

	len = 0;
	for (i=0; argv[i] != NULL; i++) {
		len += strlen(argv[i]) + 1;
	}

	buf = calloc(len, sizeof(char));
	if (buf == NULL)
		return NULL;

	for (i=0; argv[i] != NULL; i++) {
		if (i > 0)
			strlcat(buf, sep, len);
		strlcat(buf, argv[i], len);
	}

	return buf;
}

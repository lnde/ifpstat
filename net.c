/*
 * Copyright (c) 2008-2020 Andreas Lundin <lunde@dreamhosted.se>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "ifpstat.h"

/* PCAP_BUFFER_SIZE is the internal pcap buffer size in bytes */
#define PCAP_BUFFER_SIZE 	4*(1024*1024)

/*
 * PCAP_BUFFER_TIMEOUT is the packet buffer timeout in ms.
 * 900ms(<FLG_TIME) by default to limit cpu usage and prevent race
 * between announce and flush of pcap buffer.
 */
#define PCAP_BUFFER_TIMEOUT	900

/*
 * PCAP_SNAPLEN sets how many bytes of each packet is captured
 * Default is 1 byte as packet content isn't necessary.
 */
#define PCAP_SNAPLEN		1

static int set_filter(pcap_t *, const char *, const char *);

/* init_pcap initilizes the pcap_t struct so that it's ready for pcap_loop */
pcap_t *
net_init_pcap(const char *device, const char *filter,
    const pcap_direction_t direction, const int promisc)
{
	char 		 pcaperrbuf[PCAP_ERRBUF_SIZE];
	pcap_t		*pcap;
	pcap_if_t 	*pcap_devs = NULL;
	int 		 err;

	/* if no device is specified, look up the default interface */
	if (device == NULL) {
		err = pcap_findalldevs(&pcap_devs, pcaperrbuf);
		if (err == PCAP_ERROR) {
			fprintf(stderr, "Error: No suitable interface found, "
			    "try specifying one: %s\n", pcaperrbuf);
			exit(EXIT_FAILURE);
		}
		if (pcap_devs == NULL) {
			fprintf(stderr,
			    "Error: No suitable interface found, "
			    "try specifying one\n");
			exit(EXIT_FAILURE);
		}
		device = pcap_devs->name;
	}

	pcap = pcap_create(device, pcaperrbuf);
	if (pcap == NULL) {
		fprintf(stderr, "Error: %s\n", pcaperrbuf);
		exit(EXIT_FAILURE);
	}

	err = pcap_set_snaplen(pcap, PCAP_SNAPLEN);
	if (err != 0) {
		fprintf(stderr, "Warning: Failed to set snaplen, using default\n");
	}

	err = pcap_set_promisc(pcap, promisc);
	if (err != 0) {
		fprintf(stderr,
		    "Error: Failed to set interface in promiscuous mode\n");
		exit(EXIT_FAILURE);
	}

	err = pcap_set_timeout(pcap, PCAP_BUFFER_TIMEOUT);
	if (err != 0) {
		fprintf(stderr,
		    "Warning: Failed to set buffer timeout, using default.\n");
	}

	err = pcap_set_buffer_size(pcap, PCAP_BUFFER_SIZE);
	if (err != 0) {
		fprintf(stderr,
		    "Warning: Failed to set pcap buffer size, using default\n");
	}

	err = pcap_activate(pcap);
	if (err < 0) {
		fprintf(stderr, "Error: %s\n", pcap_statustostr(err));
		exit(EXIT_FAILURE);
	} else if (err > 0) {
		fprintf(stderr, "Warning: %s\n", pcap_statustostr(err));
	}

	/*
	 * Only set the direction if the user specifies 'in' or 'out'
	 * as pcap_setdirection() isn't supported on all
	 * plattforms. The default seems to be PCAP_D_INOUT if the
	 * platform doesn't support it.
	 *
	 * pcap_setdirection() MUST be called AFTER pcap_activiate()
	 * otherwise it will fail silently on at least linux. This
	 * isn't documented anywhere, used tcpdump as reference.
	 */
	if (direction != PCAP_D_INOUT) {
		err = pcap_setdirection(pcap, direction);
		if (err == PCAP_ERROR) {
			fprintf(stderr, "Error: Failed to set direction: %s\n",
			    pcap_geterr(pcap));
			exit(EXIT_FAILURE);
		}
	}

	if (filter) {
		err = set_filter(pcap, device, filter);
		if (err == PCAP_ERROR) {
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * when pcap_devs is set pcap_findalldevs() was called. Print
	 * the device name and free the memory used. */
	if (pcap_devs != NULL) {
		fprintf(stderr, "Monitoring interface %s\n", device);
		fflush(stderr);
		pcap_freealldevs(pcap_devs);
	}

	return pcap;
}

/*
 * update_drops update 'drops' counters and calculates the drop rate
 * over the given time period.
 */
void
net_update_drops(pcap_t *pcap, stats_drops_t *drops, const int64_t deltaTime)
{
	struct pcap_stat	pcap_drops;
	int			err;

	err = pcap_stats(pcap, &pcap_drops);
	if (err == PCAP_ERROR) {
		fprintf(stderr, "Error: Can't get pcap stats: %s\n",
		    pcap_geterr(pcap));
		exit(EXIT_FAILURE);
	}
	if (pcap_drops.ps_drop < drops->oldKernDrops) {
		fprintf(stderr, "Warning: drops counter rollover\n");
		drops->oldKernDrops = 0;
	}
	drops->kernDropRate =
	    (double)(pcap_drops.ps_drop - drops->oldKernDrops) /
	    deltaTime;
	drops->oldKernDrops = pcap_drops.ps_drop;

#ifndef __OpenBSD__
	if (pcap_drops.ps_ifdrop < drops->oldIfDrops) {
		fprintf(stderr, "Warning: ifdrops counter rollover\n");
		drops->oldIfDrops = 0;
	}
	drops->ifDropRate =
	    (double)(pcap_drops.ps_ifdrop - drops->oldIfDrops) /
	    deltaTime;
	drops->oldIfDrops = pcap_drops.ps_ifdrop;
#endif
	return;
}

/*
 * set_filter compiles and activates filter on pcap.
 * returns 0 on success and PCAP_ERROR on error.
 */
static int
set_filter(pcap_t *pcap, const char *device, const char *filter)
{
	char 		 	pcaperrbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	bpf_p;
	bpf_u_int32	 	netaddr;
	bpf_u_int32		netmask;
	int			err;

#ifdef PCAP_NETMASK_UNKNOWN
	netmask = PCAP_NETMASK_UNKNOWN;
#else
	netmask = 0; /* had to pick something */
#endif

	/* only lookup netmask if the filter contains "ip broadcast" */
	if (strstr(filter, "ip broadcast") != NULL) {
		/* filter with ipv4 broadcast in same subnet need netmask */
		err = pcap_lookupnet(device, &netaddr, &netmask, pcaperrbuf);
		if (err == PCAP_ERROR) {
			fprintf(stderr, "Error: Can't lookup ipv4 "
			    "network and broadcast address: %s\n",
			    pcaperrbuf);
			return PCAP_ERROR;
		}
	}

	err = pcap_compile(pcap, &bpf_p, filter, 1, netmask);
	if (err == PCAP_ERROR) {
		fprintf(stderr, "Error: Can't compile filter: %s\n",
		    pcap_geterr(pcap));
		return PCAP_ERROR;
	}

	err = pcap_setfilter(pcap, &bpf_p);
	if (err == PCAP_ERROR) {
		fprintf(stderr, "Error: Can't set filter: %s\n",
		    pcap_geterr(pcap));
		return PCAP_ERROR;
	}

	return 0;
}

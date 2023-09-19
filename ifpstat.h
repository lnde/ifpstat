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

#ifndef IFPSTAT_H
#define IFPSTAT_H

typedef struct stats_drops {
	u_int	oldKernDrops;	/* kernel drops from last announcement */
	double	kernDropRate;
#ifndef __OpenBSD__
	u_int	oldIfDrops;	/* interface drops from last announcement */
	double	ifDropRate;
#else
#warning "openbsd detected - not including ifdrops"
#endif
} stats_drops_t;

/* net.c */
pcap_t		*net_init_pcap(const char *, const char *, const pcap_direction_t,
    const int);
void		 net_update_drops(pcap_t *, stats_drops_t *, const int64_t);

/* output.c */
void	print_drops(stats_drops_t *);
void	print_header(const char *, const char, const char *);
void	print_stats(int);

#endif

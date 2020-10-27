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

#include <sys/time.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <pcap.h>

#include "ifpstat.h"

extern pcap_t	*pcap_p;
extern int	 FLG_BWDIVIDER, FLG_CNT, FLG_CSV, FLG_DROPS, FLG_PPSDIVIDER;
extern int	 FLG_TIME, FLG_TIMESTAMP;
extern int64_t	 FLG_BWMULTIPLIER;

extern int64_t 	 cntBytes;	/* counter for matched bytes */
extern int64_t 	 cntPackets;	/* counter for matched packets  */
extern time_t	 periodStart;	/* timestamp for start of measurement period */

static size_t	 str_rfc3339(char *, const size_t, const time_t *);
static int	 get_utc_offset(const time_t *);

/*
 * get_utc_offset returns the localtime() offset to UTC in seconds. A
 * positive number means it's east of UTC, a negative number means it's
 * west of UTC.
 */
static int
get_utc_offset(const time_t *ts)
{
	struct tm	*tp;
	int 		 hours, minutes;
	int 		 lhours, lminutes;
	int		 uhours, uminutes;

	/* tp points to a static struct that is overwritten by
	 * subsequent calls */
	tp = localtime(ts);
	lhours = tp->tm_hour;
	lminutes = tp->tm_min;

	tp = gmtime(ts);
	uhours = tp->tm_hour;
	uminutes = tp->tm_min;

	hours = lhours - uhours;
	minutes = lminutes - uminutes;

	return (hours*60*60) + (minutes*60);
}

void
print_drops(stats_drops_t *drops)
{
	char *fmt = "%10.0f";
	char sep = '\t';

	if (FLG_CSV) {
		fmt = "%.0f";
		sep = ',';
	}

	fprintf(stdout, fmt, drops->kernDropRate);
#ifndef __OpenBSD__
	fputc(sep, stdout);
	fprintf(stdout, fmt, drops->ifDropRate);
#endif
	return;
}

void
print_header(const char *bwPrefix, const char bwUnit, const char *packetPrefix)
{
	char bwHeader[8];
	char ppsHeader[8];
	char *ts;

	ts = "";
	if (FLG_TIMESTAMP && FLG_CSV)
		ts = "timestamp,";
	else if (FLG_TIMESTAMP)
		ts = "timestamp\t\t";

	if (FLG_CSV) {
		fprintf(stdout, "%s%s%cps,%spps", ts,
		    bwPrefix, bwUnit, packetPrefix);
		if (FLG_DROPS) {
			fprintf(stdout, ",drops");
#ifndef __OpenBSD__
			fprintf(stdout, ",ifdrops");
#endif
		}
		fprintf(stdout, "\n");
		return;
	}

	snprintf(bwHeader, sizeof(bwHeader), "%s%cps", bwPrefix,
	    bwUnit);
	snprintf(ppsHeader, sizeof(ppsHeader), "%spps", packetPrefix);
	fprintf(stdout, "%s%10s\t%10s", ts,  bwHeader, ppsHeader);

	if (FLG_DROPS) {
		fprintf(stdout, "\t%10s", "drops");
#ifndef __OpenBSD__
		fprintf(stdout, "\t%10s", "ifdrops");
#endif
	}
	fprintf(stdout, "\n");
	return;
}

/* print_stats prints bandwidth and packet rate to stdout */
void
print_stats(int unused)
{
	static stats_drops_t	drops;

	char 		tsbuf[32]; 	/* timestamp buffer */
	static int64_t 	announceCount; 	/* counter for the announcements */
	static int64_t 	oldBytes;	/* bytes from last announcement */
	static int64_t 	oldPackets;	/* packets from last announcement */
	int64_t 	deltaBytes;
	int64_t 	deltaPackets;
	int64_t		deltaTime;
	double		byteRate, packetRate;

	deltaBytes = cntBytes - oldBytes;
	deltaPackets = cntPackets - oldPackets;
	oldBytes = cntBytes;
	oldPackets = cntPackets;
	announceCount++;

	deltaTime = FLG_TIME;
	/* FLG_TIME is 0 when announced is triggered on a signal */
	if (FLG_TIME == 0) {
		time_t now;

		now = time(NULL);
		deltaTime = now - periodStart;
		/* if announce is called more than once a second via signal
		 * this ensures that we don't divide by zero */
		if (deltaTime <= 0)
			deltaTime = 1;
		periodStart = now;
	}

	if (FLG_TIMESTAMP) {
		time_t 		 now;
		struct tm	*tp;

		now = time(NULL);
		tp = localtime(&now);
		if (tp == NULL) {
			fprintf(stderr, "Error: Failed to get local time");
			exit(EXIT_FAILURE);
		}

		if (FLG_CSV) {
			/* use rfc3339 timestamp */
			if (str_rfc3339(tsbuf, sizeof(tsbuf), &now) == 0) {
				fprintf(stderr, "Error: Failed to create time stamp");
				exit(EXIT_FAILURE);
			}
		} else {
			/* yyyy-mm-dd hh:mm:ss */
			if (strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %T", tp) == 0) {
				fprintf(stderr, "Error: Failed to create time stamp");
				exit(EXIT_FAILURE);
			}
		}
	}

	byteRate = (deltaBytes / (double)FLG_BWDIVIDER) / deltaTime;
	packetRate = (deltaPackets / (double)FLG_PPSDIVIDER) / deltaTime;

	if (FLG_DROPS) {
		net_update_drops(pcap_p, &drops, deltaTime);
	}

	if (FLG_CSV) {
		if (FLG_TIMESTAMP) {
			fprintf(stdout, "%s", tsbuf);
			fputc(',', stdout);
		}
		if (FLG_BWDIVIDER > 1)
			fprintf(stdout, "%.2f", byteRate * FLG_BWMULTIPLIER);
		else
			fprintf(stdout, "%.0f", byteRate * FLG_BWMULTIPLIER);
		fputc(',', stdout);
		if (FLG_PPSDIVIDER > 1)
			fprintf(stdout, "%.2f", packetRate);
		else
			fprintf(stdout, "%.0f", packetRate);
		if (FLG_DROPS) {
			fputc(',', stdout);
			print_drops(&drops);
		}
	} else {
		if (FLG_TIMESTAMP) {
			fprintf(stdout, "%s", tsbuf);
			fputc('\t', stdout);
		}
		if (FLG_BWDIVIDER > 1)
			fprintf(stdout, "%10.2f", byteRate * FLG_BWMULTIPLIER);
		else
			fprintf(stdout, "%10.0f", byteRate * FLG_BWMULTIPLIER);
		fputc('\t', stdout);
		if (FLG_PPSDIVIDER > 1)
			fprintf(stdout, "%10.2f", packetRate);
		else
			fprintf(stdout, "%10.0f", packetRate);
		if (FLG_DROPS) {
			fputc('\t', stdout);
			print_drops(&drops);
		}
	}

	fprintf(stdout, "\n");
	fflush(stdout);

	if (announceCount == FLG_CNT)
		exit(EXIT_SUCCESS);
}

/*
 * str_rfc3339 writes an rfc3339 formatted timestamp from tp into buf.
 * Returns 0 on error and bytes written into buffer on success.
 */
static size_t
str_rfc3339(char *buf, const size_t bufSize, const time_t *ts)
{
	struct tm	*tp;
	char 		 tsbuf[32];
	char 		 utcOffsetBuf[8];
	int		 offset, hours, minutes;
	size_t		 ret;
	char		 c;

	offset = get_utc_offset(ts);
	if (offset == 0) {
		/* rfc3339 - 2006-01-02T15:04:05Z */
		return strftime(buf, bufSize, "%Y-%m-%dT%TZ", localtime(ts));
	} else if (offset > 0) {
		c = '+';
	} else {
		c = '-';
		offset = offset * -1;
	}
	/* include timezone offset - rfc3339 - 2006-01-02T15:04:05+06:00 */
	hours = offset / 3600;
	minutes = (offset / 60) % 60;
	ret = snprintf(utcOffsetBuf, sizeof(utcOffsetBuf),
	    "%c%.2d:%.2d", c, hours, minutes);
	if (ret >= sizeof(utcOffsetBuf))
		return 0;

	tp = localtime(ts);
	if (tp == NULL) {
		fprintf(stderr, "Error: Failed to get local time");
		exit(EXIT_FAILURE);
	}

	ret = strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%dT%T", tp);
	if (ret == 0)
		return ret;

	ret = snprintf(buf, bufSize, "%s%s", tsbuf, utcOffsetBuf);
	if (ret >= bufSize)
		return 0;

	return ret;
}

# ifpstat
**ifpstat** -- report network interface statistics based on pcap-filter(7).

# Description
**ifpstat** reports bandwidth and packet rate of a network interface to stdout.
It's possible to control the reported interface statistics by specifying an
optional pcap-filter(7) **expression**.

If no interface is specified **ifpstat** will use pcap to find a default
interface and print the selected interface to stderr.

The default bandwidth output is in KiBps and the default packet rate
is in packets per second (pps).

# Usage
	ifpstat	[-BbCDhKMmnptv] [-c count] [-d in|out|any] [-i interface]
		[-w delay] [expression]
	-B		Bandwidth in bytes/bits per second instead of
			kilo bit/bytes.
	-b		Bandwidth in bits per second instead of bytes.
	-C		Output as Comma-Separated-Values (CSV).
	-c count	Exit after count number of reports.
	-D		Print packet drop statistics from pcap_stats(3).
			See CAVEATS section for details.
	-d direction	Report only specified direction. Accepted values are
			'in', 'out' and 'any'. Default is 'any'.
	-h		Usage.
	-i interface	Specify which interface to monitor.
	-K		Packet rate in thousand packets per second (Kpps).
	-m		Bandwidth in mega bit/bytes per second.
	-M		Packet rate in million packets per second (Mpps).
	-n		Don't print the header.
	-p		Set interface in promiscuous mode.
	-t		Include local time stamp for each report. The default
			format is human readable but in RFC3339 format if the
			output is CSV.
	-v		Print version and exit.
	-w seconds	Wait wait seconds between each report. If wait is 0
			ifpstat prints the report upon receiving signal USR1.
			Any following USR1 signals and the report is based on
			data between the last two signals.

# Example
Show http/https traffic in 5 seconds interval on interface en0.

	# ifpstat -tw 5 -i en0 port http or port https
	timestamp     	   	     KiBps	       pps
	2020-07-01 12:00:00	    558.36	       525
	2020-07-01 12:00:05	   5194.69	      4589
	2020-07-01 12:00:10	   3413.73	      2594
	2020-07-01 12:00:15	    324.20	       251

# See Also
[pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html),
[pcap_stats(3)](https://www.tcpdump.org/manpages/pcap_stats.3pcap.html)

# License
Copyright (c) 2008-2020 Andreas Lundin, &lt;lunde@dreamhosted.se&gt;

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# CAVEATS
The **-D** option is based on pcap_stats(3) which isn't very reliable. You
should check if it's supported on your plattform. The drops counter is
from ps_drop and ifdrop is from ps_ifdrop.

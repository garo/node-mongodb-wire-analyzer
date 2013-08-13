node-mongodb-wire-analyzer
==========================

MongoDB wire sniffer with optional statsd/graphite output for statistics

This program used libpcap to intercept all mongodb commands, parses the mongodb binary wire protocol
and outputs the queries to stdout and/or sends statistic counters to statsd/graphite.

Usage: node ./analyze.js --interface <interface name from ifconfig>
Optional arguments:

	--stdout
		Print query data to stdout (in ugly json)

	--filter <tcpdump filter>
		Default filter string is "dst port 27017"

	--statsd <host>
		Sends update/insert/query statistics to statsd/graphite server.

	--statsd-port <port>
		Sets statsd port. default port is 8125.

	--statsd-prefix <prefix name>
		Prefix for statsd. Default prefix is "mongodb.wirestats"

Issues, feedback etc at https://github.com/garo/node-mongodb-wire-analyzer

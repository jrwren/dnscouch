package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/jrwren/dnscouch"
)

func main() {
	n := flag.Int("c", 1, "count - number of lookups to make per server")
	useIPv6 := flag.Bool("6", false, "query IPv6 servers (DNS only)")
	flag.Parse()
	dnsServers := dnscouch.ServerMap4
	if *useIPv6 {
		dnsServers = dnscouch.ServerMap6
	}
	for i := 0; i < *n; i++ {
		times, err := dnscouch.TimeDNSLookupServers(dnsServers)
		if err != nil {
			log.Print("error:", err)
		}
		for server, t := range times {
			desc := dnsServers[server]
			fmt.Printf("%d, %v %v %v\n", i, t, server, desc)
		}
	}
}

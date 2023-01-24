package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/jrwren/dnscouch"
)

func main() {
	n := flag.Int("c", 1, "count - number of lookups to make per server")
	flag.Parse()
	for i := 0; i < *n; i++ {
		times, err := dnscouch.TimeDNSLookupServers()
		if err != nil {
			log.Print("error:", err)
		}
		for server, t := range times {
			desc := dnscouch.ServerMap[server]
			fmt.Printf("%d, %v %v %v\n", i, t, server, desc)
		}
	}
}

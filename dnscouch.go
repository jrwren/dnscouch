package dnscouch

import (
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var ServerMap = map[string]string{
	"1.1.1.1":         "Cloudflare One",
	"8.8.8.8":         "Google",
	"9.9.9.9":         "Quad9 filtered",
	"149.112.112.112": "Quad9 filtered",
	"208.67.222.222":  "Opendns",
	"208.67.220.220":  "Opendns",
	"4.2.2.1":         "Level 3",
	"209.244.0.3":     "Level 3",
	"209.244.0.4":     "Level 3",
	"9.9.9.10":        "Quad9 unfiltered",
	"149.112.112.10":  "Quad9 unfiltered",
	"9.9.9.11":        "Quad9 ecs unfiltered",
	"149.112.112.11":  "Quad9 ecs unfiltered",
	"68.94.156.1":     "ATT Primary",
	"68.94.157.1":     "ATT Secondary",
	"12.121.117.201":  "ATT Services",
}

// EnableComcast enables comcast DNS servers. They don't response from outside
// the comcast network.
func EnableComcast() {
	comcast := map[string]string{
		"75.75.75.75":           "Comcast Primary",
		"75.75.76.76":           "Comcast Secondary",
		"[2001:558:feed::1]:53": "Comcast Primary IPv6",
		"[2001:558:feed::2]:53": "Comcast Secondary IPv6",
		"68.87.85.102":          "Comcast older Primary",
		"68.87.64.150":          "Comcast older Secondary",
	}
	for s, p := range comcast {
		ServerMap[s] = p
	}
}

func TimeDNSLookup(server string) (time.Duration, error) {
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}
	now := time.Now()
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("google.com.", dns.TypeA)
	_, _, err := c.Exchange(m, server)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return 2 * time.Second, nil // miekg.dns timeout default is 2s.
	}
	return -time.Until(now), err
}

type Result struct {
	ServerName, Desc string
	D                time.Duration
}

type Results []Result

func (a Results) Len() int           { return len(a) }
func (a Results) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Results) Less(i, j int) bool { return a[i].D < a[j].D }

func TimeDNSLookupServers() (map[string]time.Duration, error) {
	times := make(map[string]time.Duration, len(ServerMap))
	for s := range ServerMap {
		t, err := TimeDNSLookup(s)
		if err != nil {
			return times, err
		}
		times[s] = t
	}
	return times, nil
}

func LookupServers() (Results, error) {
	var r Results
	times, err := TimeDNSLookupServers()
	if err != nil {
		return nil, err
	}
	for s, t := range times {
		r = append(r, Result{s, ServerMap[s], t})
	}
	sort.Sort(r)
	return r, nil
}

func TimeDNSLookupServersAvg(n int) (map[string]time.Duration, error) {
	times := make(map[string]time.Duration, len(ServerMap))
	for i := 0; i < n; i++ {
		for s := range ServerMap {
			t, err := TimeDNSLookup(s)
			if err != nil {
				return times, err
			}
			times[s] = t
		}
	}
	return times, nil
}

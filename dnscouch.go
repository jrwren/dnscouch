package dnscouch

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/beevik/ntp"
	"github.com/miekg/dns"
)

var ServerMap4 = map[string]string{
	"1.1.1.1":        "Cloudflare One",
	"1.0.0.1":        "Cloudflare One",
	"8.8.8.8":        "Google Primary",
	"8.8.4.4":        "Google Secondary",
	"208.67.222.222": "OpenDNS Primary",
	"208.67.220.220": "OpenDNS Secondary",
	"4.2.2.1":        "Level 3",
	"209.244.0.3":    "Level 3",
	"209.244.0.4":    "Level 3",
	"9.9.9.10":       "Quad9 unfiltered",
	"149.112.112.10": "Quad9 unfiltered",
	"68.94.156.1":    "ATT Primary",
	"68.94.157.1":    "ATT Secondary",
	"12.121.117.201": "ATT Services",
	"8.26.56.26":     "Comodo Primary",
	"8.20.247.20":    "Comodo Secondary",
	"76.76.2.0":      "Control D Primary",
	"76.76.10.0":     "Control D Secondary",
	"185.228.168.9":  "Clean Browsing Primary",
	"185.228.169.9":  "Clean Browsing Secondary",
	"76.76.19.19":    "Alternate DNS Primary",
	"76.223.122.150": "Alternate DNS Secondary",
	"94.140.14.14":   "AdGuard DNS Primary",
	"94.140.15.15":   "AdGuard DNS Secondary",
}

var ServerMap6 = map[string]string{
	"[2606:4700:4700::1111]": "Cloudflare One",
	"[2606:4700:4700::1001]": "Cloudflare One",
	"[2001:4860:4860::8888]": "Google Primary",
	"[2001:4860:4860::8844]": "Google Secondary",
	"[2620:119:35::35]":      "OpenDNS Primary",
	"[2620:119:53::53]":      "OpenDNS Secondary",
	// Couldn't find IPv6 values for Level 3
	"[2620:fe::fe]": "Quad9 unfiltered",
	"[2620:fe::9]":  "Quad9 unfiltered",
	// Couldn't find IPv6 values for ATT
	// Couldn't find IPv6 values for Comodo
	"[2606:1a40::]":       "Control D Primary",
	"[2606:1a40:1::]":     "Control D Secondary",
	"[2a0d:2a00:1::]":     "Clean Browsing Primary",
	"[2a0d:2a00:2::]":     "Clean Browsing Secondary",
	"[2602:fcbc::ad]":     "Alternate DNS Primary",
	"[2602:fcbc:2::ad]":   "Alternate DNS Secondary",
	"[2a10:50c0::ad1:ff]": "AdGuard DNS Primary",
	"[2a10:50c0::ad2:ff]": "AdGuard DNS Secondary",
}

var FilteredServerMap = map[string]string{
	"1.1.1.2":         "Cloudflare Malware Filtered",
	"1.0.0.2":         "Cloudflare Malware Filtered",
	"1.1.1.3":         "Cloudflare Adult Filtered",
	"1.0.0.3":         "Cloudflare Adult Filtered",
	"9.9.9.9":         "Quad9 filtered Primary",
	"149.112.112.112": "Quad9 filtered Secondary",
	// Not technically a filter, but a strange, rare feature:
	// EDNS Client-Subnet.
	// More about ECS here: https://www.isc.org/blogs/quad9-2020-06/ and
	// here: https://www.quad9.net/support/faq/#edns
	"9.9.9.11":       "Quad9 ecs unfiltered",
	"149.112.112.11": "Quad9 ecs unfiltered",
}

// EnableComcast enables comcast DNS servers. They don't response from outside
// the comcast network.
func EnableComcast(servers map[string]string) {
	comcast := map[string]string{
		"75.75.75.75": "Comcast Primary",
		"75.75.76.76": "Comcast Secondary",
		//		"[2001:558:feed::1]:53": "Comcast Primary IPv6",
		//		"[2001:558:feed::2]:53": "Comcast Secondary IPv6",
		"68.87.85.102": "Comcast older Primary",
		"68.87.64.150": "Comcast older Secondary",
	}
	for s, p := range comcast {
		servers[s] = p
	}
}

func TimeDNSLookup(server string) (time.Duration, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return 0, fmt.Errorf("TimeDNSLookup[%q]: %w", server, err)
		}
		server += ":53"
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("google.com.", dns.TypeA)
	start := time.Now()
	_, _, err := c.Exchange(m, server)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return 2 * time.Second, nil // miekg.dns timeout default is 2s.
	}
	return time.Since(start), err
}

type Result struct {
	ServerName, Desc string
	D                time.Duration
}

type Results []Result

func (a Results) Len() int           { return len(a) }
func (a Results) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Results) Less(i, j int) bool { return a[i].D < a[j].D }

func TimeDNSLookupServers(servers map[string]string) (map[string]time.Duration, error) {
	times := make(map[string]time.Duration, len(servers))
	for s := range servers {
		t, err := TimeDNSLookup(s)
		if err != nil {
			return times, err
		}
		times[s] = t
	}
	return times, nil
}

func LookupServers(servers map[string]string) (Results, error) {
	var r Results
	times, err := TimeDNSLookupServers(servers)
	if err != nil {
		return nil, err
	}
	for s, t := range times {
		r = append(r, Result{s, servers[s], t})
	}
	sort.Sort(r)
	return r, nil
}

func LookupServersN(servers map[string]string, n int) (Results, error) {
	var r Results
	var allTimes []map[string]time.Duration
	for i := 0; i < n; i++ {
		t, err := TimeDNSLookupServers(servers)
		if err != nil {
			return nil, err
		}
		allTimes = append(allTimes, t)
	}
	times := make(map[string]time.Duration, len(servers))
	for s := range servers {
		sum := int64(0)
		for i := 0; i < n; i++ {
			sum += int64(allTimes[i][s])
		}
		avg := sum / int64(n)
		times[s] = time.Duration(avg)
	}
	for s, t := range times {
		r = append(r, Result{s, servers[s], t})
	}
	sort.Sort(r)
	return r, nil
}

func TimeDNSLookupServersAvg(servers map[string]string, n int) (map[string]time.Duration, error) {
	times := make(map[string]time.Duration, len(servers))
	for i := 0; i < n; i++ {
		for s := range servers {
			t, err := TimeDNSLookup(s)
			if err != nil {
				return times, err
			}
			times[s] = t
		}
	}
	return times, nil
}

var NTPServerMap = map[string]string{
	"time.cloudflare.com":   "Cloudflare time",
	"ntp.ubuntu.com":        "NTP Ubuntu",
	"0.ubuntu.pool.ntp.org": "NTP Ubuntu 0",
	"1.ubuntu.pool.ntp.org": "NTP Ubuntu 1",
	"2.ubuntu.pool.ntp.org": "NTP Ubuntu 2",
	"ntp.nexcess.net":       "NexcessNet",
	"time.nist.gov":         "NIST",
	"pool.ntp.org":          "NTP org pool",
	"0.pool.ntp.org":        "NTP org pool 0",
	"1.pool.ntp.org":        "NTP org pool 1",
	"2.pool.ntp.org":        "NTP org pool 2",
	"time1.google.com":      "Google time",
	"time2.google.com":      "Google time",
	"time3.google.com":      "Google time",
	"time4.google.com":      "Google time",
	"time.windows.com":      "Windows time",
	"time.apple.com":        "Apple time",
	// Intentionally not adding time.facebook.com because facebook is evil AND
	// because I DNS sinkhole facebook DNS properties in my home so I cannot
	// test it. 😀
	// Intentionally not adding russian servers from:
	// https://gist.github.com/mutin-sa/eea1c396b1e610a2da1e5550d94b0453
	// because Russia is evil and untrustworthy.
	// Intentinonlly not adding a lot of stuff because there are so many.
	// TODO: regional server list options for EU, NA, ASIA
	"ntp1.hetzner.de":       "Hetzner Online 1",
	"ntp2.hetzner.de":       "Hetzner Online 2",
	"ntp3.hetzner.de":       "Hetzner Online 3",
	"ntp.ripe.net":          "RIPE",
	"clock.isc.org":         "ISC",
	"0.amazon.pool.ntp.org": "Amazon 0",
	"1.amazon.pool.ntp.org": "Amazon 1",
	"2.amazon.pool.ntp.org": "Amazon 2",
	"3.amazon.pool.ntp.org": "Amazon 3",
}

func LookupNTPServersN(n int) (Results, error) {
	var r Results
	var allTimes []map[string]time.Duration
	for i := 0; i < n; i++ {
		if i > 0 {
			// NTP Servers can throttle aggressively.
			// e.g. kiss of death received: RATE
			time.Sleep(2 * time.Second)
		}
		t, err := TimeNTPLookupServers()
		if err != nil {
			return nil, err
		}
		allTimes = append(allTimes, t)
	}
	times := make(map[string]time.Duration, len(NTPServerMap))
	for s := range NTPServerMap {
		sum := int64(0)
		for i := 0; i < n; i++ {
			sum += int64(allTimes[i][s])
		}
		avg := sum / int64(n)
		times[s] = time.Duration(avg)
	}
	for s, t := range times {
		r = append(r, Result{s, NTPServerMap[s], t})
	}
	sort.Sort(r)
	return r, nil
}

func TimeNTPLookupServers() (map[string]time.Duration, error) {
	times := make(map[string]time.Duration, len(NTPServerMap))
	for s := range NTPServerMap {
		t, err := TimeNTPLookup(s)
		if err != nil {
			return times, err
		}
		times[s] = t
	}
	return times, nil
}

func TimeNTPLookup(server string) (time.Duration, error) {
	now := time.Now()
	_, err := ntp.Time(server)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return 5 * time.Second, nil // miekg.dns timeout default is 2s.
	}
	return -time.Until(now), err
}

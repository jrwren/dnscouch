# dnscouch

Not a bench, more like a couch.

Obligatory screenshot:

![dnscouchT screenshot](/screenshot-dnscouchT.png)

## Aboot

There are 2 commands:

* dnscouchT - a curses based table of results sorted by response time
* dnscouch - raw csv formatted results, suitable for scripts / metrics ingestion.

## Installation

```sh
go install github.com/jrwren/dnscouch/cmd/dnscouchT@latest
```

## Running

```sh
dnscouchT
```

### NTP

Invoke `dnscouchT` with the `-t` option to time NTP servers instaed of DNS
servers.

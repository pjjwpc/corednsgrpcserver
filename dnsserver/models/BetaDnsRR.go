package models

import "github.com/miekg/dns"

type BetaDnsRR struct {
	Id    int64  `json:"id"`
	DnsRR dns.RR `json:"dns_rr"`
}

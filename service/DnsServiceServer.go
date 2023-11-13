package service

import (
	"context"
	"dnsadminserver/config"
	"log"

	"github.com/coredns/coredns/pb"
	"github.com/miekg/dns"
	"google.golang.org/grpc/metadata"
	// "google.golang.org/grpc/peer"
)

type BetaDnsServiceServer struct {
	pb.UnimplementedDnsServiceServer
}

func (s *BetaDnsServiceServer) Query(ctx context.Context, req *pb.DnsPacket) (resp *pb.DnsPacket, err error) {
	reqMsg := new(dns.Msg)
	err = reqMsg.Unpack(req.Msg)
	if err != nil {
		log.Println(err)

		return resp, nil
	}
	me, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Println("metadata not found")

		return resp, nil
	}
	cluster := me.Get("cluster")[0]
	records := make([]dns.RR, 0)
	for _, v := range reqMsg.Question {
		key := cluster + " " + v.Name
		rdata := config.DnsRecordsCache[key]
		for _, r := range rdata {
			if r.Header().Rrtype == v.Qtype {
				records = append(records, r)
			}
		}
	}
	if len(records) == 0 {
		log.Println("no records found", reqMsg.Question)
	}

	msg := new(dns.Msg)
	msg.SetReply(reqMsg)
	msg.Authoritative = true
	msg.Answer = records
	responseBytes, err := msg.Pack()
	if err != nil {
		log.Fatalf("Error packing DNS response: %v", err)
		return resp, nil
	}
	resp = new(pb.DnsPacket)
	resp.Msg = responseBytes
	return resp, nil
}

package main

import (
	"dnsadminserver/internal/service"
	"fmt"
	"log"
	"net"

	"os"

	pb "github.com/coredns/coredns/pb"
	"google.golang.org/grpc"
)

func main() {
	servicePort := os.Getenv("ServicePort")
	if servicePort == "" {
		servicePort = "8050"
	}
	grpcServer := grpc.NewServer()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", servicePort))
	if err != nil {
		log.Fatal(err)
	}

	pb.RegisterDnsServiceServer(grpcServer, &service.DnsServiceServer{})
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal(err)
	}
}

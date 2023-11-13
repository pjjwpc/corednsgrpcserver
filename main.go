package main

import (
	_ "betadnsadminserver/plugin/forward"
	"betadnsadminserver/service"
	pb "github.com/coredns/coredns/pb"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	grpcServer := grpc.NewServer()
	lis, err := net.Listen("tcp", ":8050")
	if err != nil {
		log.Fatal(err)
	}

	// Register the service with the server

	pb.RegisterDnsServiceServer(grpcServer, &service.BetaDnsServiceServer{})
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal(err)
	}

}

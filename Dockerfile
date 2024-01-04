FROM golang:1.20 as build
WORKDIR /src
COPY . .
RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN go build 

FROM harbor.betawm.com/go/gobase:v0.1 as base
WORKDIR /beta
COPY --from=build /src/betadnsadminserver .
RUN chmod +x /beta/betadnsadminserver

ENTRYPOINT [ "/beta/betadnsadminserver" ]


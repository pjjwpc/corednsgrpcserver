FROM golang:1.18 as build
WORKDIR /src
COPY . .
RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN go build

FROM centos:centos7 as final
WORKDIR /beta
COPY --from=build /src/betadnsadminserver .
RUN chmod +x /beta/betadnsadminserver

ENTRYPOINT [ "/beta/betadnsadminserver" ]


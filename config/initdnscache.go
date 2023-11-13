package config

import (
	"context"
	"dnsadminserver/models"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

var DnsRecordsCache map[string][]dns.RR

func buildDnsRecordsCache(dnsRecordsList []models.DnsRecords, clear bool) {
	clearKey := map[string]bool{} // 防止重复清理
	for _, v := range dnsRecordsList {
		keyname := v.ClusterName + " " + v.Name
		if clear && !clearKey[keyname] {
			DnsRecordsCache[keyname] = []dns.RR{}
			clearKey[keyname] = true // 防止重复清理
		}

		switch v.Qtype {
		case dns.TypeA:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					A: net.ParseIP(v.Rdata),
				})
		case dns.TypeAAAA:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					AAAA: net.ParseIP(v.Rdata),
				})
		case dns.TypeCNAME:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Target: v.Rdata,
				})
		case dns.TypeTXT:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.TXT{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Txt: []string{v.Rdata},
				})
		case dns.TypeMX:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.MX{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Mx: v.Rdata,
				})
		case dns.TypeNS:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Ns: v.Rdata,
				})
		case dns.TypeSRV:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.SRV{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeSRV,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Target: v.Rdata,
				})
		case dns.TypeSOA:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeSOA,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Ns: v.Rdata,
				})
		case dns.TypePTR:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.PTR{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Ptr: v.Rdata,
				})
		case dns.TypeCAA:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.CAA{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeCAA,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Value: v.Rdata,
				})
		case dns.TypeNAPTR:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.NAPTR{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeNAPTR,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Flags: v.Rdata,
				})
		case dns.TypeTLSA:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.TLSA{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeTLSA,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Certificate: v.Rdata,
				})
		case dns.TypeDS:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.DS{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeDS,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Digest: v.Rdata,
				})
		case dns.TypeSSHFP:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.SSHFP{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeSSHFP,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					FingerPrint: v.Rdata,
				})
		case dns.TypeDNSKEY:
			log.Println("暂未支持DNSKEY")
		case dns.TypeRRSIG:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.RRSIG{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeRRSIG,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Signature: v.Rdata,
				})
		case dns.TypeNSEC:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.NSEC{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeNSEC,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					NextDomain: v.Rdata,
				})
		case dns.TypeNSEC3:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.NSEC3{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeNSEC3,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					NextDomain: v.Rdata,
				})
		case dns.TypeNSEC3PARAM:
			DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname],
				&dns.NSEC3PARAM{
					Hdr: dns.RR_Header{
						Name:   v.Name,
						Rrtype: dns.TypeNSEC3PARAM,
						Class:  dns.ClassINET,
						Ttl:    v.Ttl,
					},
					Salt: v.Rdata,
				})
		default:
			log.Println("initdnscache.go: init() error: ", "未知的类型")

		}
	}
}

func init() {
	DnsRecordsCache = make(map[string][]dns.RR)
	go subRedis()

	// 查询所有的域名放入内存缓存
	DnsRecordsList := getDnsRecords("", "")
	buildDnsRecordsCache(DnsRecordsList, false)
	log.Println("initdnscache.go: init() success: ", "初始化缓存成功", DnsRecordsCache)
}

func getDnsRecords(name string, qtype string) (list []models.DnsRecords) {
	sql := `select id,
            (select cluster_name from envoy_cluster where id=cluster_id) as cluster_name,
            name,qtype,qclass,ttl,rdata,
            create_user,create_time,update_user,update_time
            from dns_records where is_delete=0`
	if name != "" {
		sql += fmt.Sprintf(" and name='%s'", name)
	}
	if qtype != "" {
		sql += fmt.Sprintf(" and qtype=%s", qtype)
	}
	err := Orm.Raw(sql).Find(&list).Error
	if err != nil {
		log.Println("initdnscache.go: init() error: ", err)
		panic(err)

	}
	return
}

func subRedis() {
	// name+qtype
	ctx := context.Background()
	pubsub := RedisDb.Subscribe(ctx, RedisChannel)
	defer pubsub.Close()
	ch := pubsub.Channel()
	for msg := range ch {
		log.Printf("收到变更消息：%s", msg.Payload)
		op_signal := strings.Split(msg.Payload, ":")
		if len(op_signal) != 2 {
			log.Println("从redis接收到的数据不正确，不做处理，消息内容：", msg.Payload)
			continue
		}

		DnsRecordsList := getDnsRecords(op_signal[0], op_signal[1])
		log.Println("initdnscache.go: subRedis() success: ", "更新缓存成功", DnsRecordsList)

		buildDnsRecordsCache(DnsRecordsList, true)

		continue
	}
}

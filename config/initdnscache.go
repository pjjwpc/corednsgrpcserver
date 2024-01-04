package config

import (
	"betadnsadminserver/models"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var DnsRecordsCache map[string][]models.BetaDnsRR

func buildDR(v models.DnsRecords) (dr models.BetaDnsRR) {
	switch v.Qtype {
	case dns.TypeA:
		return models.BetaDnsRR{
			DnsRR: &dns.A{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				A: net.ParseIP(v.Rdata),
			},
			Id: v.Id,
		}
	case dns.TypeAAAA:
		return models.BetaDnsRR{
			DnsRR: &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				AAAA: net.ParseIP(v.Rdata),
			}, Id: v.Id,
		}
	case dns.TypeCNAME:
		return models.BetaDnsRR{
			DnsRR: &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Target: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeTXT:
		return models.BetaDnsRR{
			DnsRR: &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Txt: []string{v.Rdata},
			},
			Id: v.Id,
		}
	case dns.TypeMX:
		return models.BetaDnsRR{
			DnsRR: &dns.MX{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Mx: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeNS:
		return models.BetaDnsRR{
			DnsRR: &dns.NS{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Ns: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeSRV:
		return models.BetaDnsRR{
			DnsRR: &dns.SRV{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Target: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeSOA:
		return models.BetaDnsRR{
			DnsRR: &dns.SOA{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Ns: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypePTR:
		return models.BetaDnsRR{
			DnsRR: &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Ptr: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeCAA:
		return models.BetaDnsRR{
			DnsRR: &dns.CAA{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeCAA,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Value: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeNAPTR:
		return models.BetaDnsRR{
			DnsRR: &dns.NAPTR{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeNAPTR,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Flags: v.Rdata,
			},
			Id: v.Id,
		}

	case dns.TypeTLSA:
		return models.BetaDnsRR{
			DnsRR: &dns.TLSA{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeTLSA,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Certificate: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeDS:
		return models.BetaDnsRR{
			DnsRR: &dns.DS{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Digest: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeSSHFP:
		return models.BetaDnsRR{
			DnsRR: &dns.SSHFP{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeSSHFP,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				FingerPrint: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeDNSKEY:
		log.Println("暂未支持DNSKEY")
	case dns.TypeRRSIG:
		return models.BetaDnsRR{
			DnsRR: &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeRRSIG,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Signature: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeNSEC:
		return models.BetaDnsRR{
			DnsRR: &dns.NSEC{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeNSEC,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				NextDomain: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeNSEC3:
		return models.BetaDnsRR{
			DnsRR: &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeNSEC3,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				NextDomain: v.Rdata,
			},
			Id: v.Id,
		}
	case dns.TypeNSEC3PARAM:
		return models.BetaDnsRR{
			DnsRR: &dns.NSEC3PARAM{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: dns.TypeNSEC3PARAM,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				Salt: v.Rdata,
			},
			Id: v.Id,
		}
	default:
		log.Println("initdnscache.go: init() error: ", "未知的类型")
	}
	return dr
}
func buildDnsRecordsCache(dnsRecordsList []models.DnsRecords, clear bool) {
	clearKey := map[string]bool{} // 防止重复清理
	for _, v := range dnsRecordsList {
		keyname := v.ClusterName + "-" + fmt.Sprint(v.Qtype) + "-" + v.Name
		if clear && !clearKey[keyname] {
			DnsRecordsCache[keyname] = []models.BetaDnsRR{}
			clearKey[keyname] = true // 防止重复清理
		}
		dr := buildDR(v)
		if dr.Id <= 0 {
			continue
		}
		DnsRecordsCache[keyname] = append(DnsRecordsCache[keyname], dr)
	}
}

func init() {
	DnsRecordsCache = make(map[string][]models.BetaDnsRR)
	go subRedis()
	// 查询所有的域名放入内存缓存
	DnsRecordsList := getDnsRecords(0, "", "")
	if len(DnsRecordsList) == 0 {
		log.Println("initdnscache.go: init() error: ", "数据库拉取dns配置失败,从缓存文件获取")
		DnsRecordsList = getDnsRecordsByFile()
	} else if Config.IsMaster { // 主节点将从数据库中查询到的记录写入缓存文件
		// 写入缓存文件
		file, err := os.OpenFile(Config.CacheFile, os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Println("initdnscache.go: init() error: ", "打开缓存文件失败")
		}
		defer file.Close()
		// 创建json编码器
		encoder := json.NewEncoder(file)
		// 将结构体数据编码到文件中
		err = encoder.Encode(DnsRecordsList)
		if err != nil {
			log.Println("initdnscache.go: init() error: ", "写入缓存文件失败")
		}
	}
	buildDnsRecordsCache(DnsRecordsList, false)
	log.Println("initdnscache.go: init() success: ", "初始化缓存成功", DnsRecordsCache)
}

func getDnsRecords(clusterId int64, name string, qtype string) (list []models.DnsRecords) {
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
	if clusterId > 0 {
		sql += fmt.Sprintf(" and cluster_id=%d", clusterId)
	}
	log.Println(sql)
	err := Orm.Raw(sql).Find(&list).Error
	if err != nil {
		log.Println("数据库查询数据失败:", err, sql)
	}
	return
}

func getDnsRecordsByFile() (list []models.DnsRecords) {
	log.Println("数据库拉取dns配置失败,从缓存文件获取")
	// 判断文件是否存在
	_, err := os.Stat(Config.CacheFile)
	if os.IsNotExist(err) {
		log.Println("initdnscache.go: init() error: ", "缓存文件不存在")
		return
	}

	file, err := os.Open(Config.CacheFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	// 读取文件内容
	decoder := json.NewDecoder(file)
	// 将文件内容解析到结构体中
	err = decoder.Decode(&list)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func subRedis() {
	ctx := context.Background()
	pubsub := RedisDb.Subscribe(ctx, RedisChannel)
	defer pubsub.Close()
	ch := pubsub.Channel()
	for msg := range ch {
		log.Printf("收到变更消息：%s", msg.Payload)
		if strings.HasSuffix(msg.Payload, "delete") {
			op_signal := strings.Split(msg.Payload, ":")
			if len(op_signal) != 3 {
				log.Println("从redis接收到的数据不正确，不做处理，消息内容：", msg.Payload)
				continue
			}
			cacheDr, ok := DnsRecordsCache[op_signal[0]]
			if ok {
				result := []models.BetaDnsRR{}
				for i, v := range cacheDr {
					id, err := strconv.ParseInt(op_signal[1], 10, 64)
					if err != nil {
						continue
					}
					if v.Id != id {
						result = append(result, cacheDr[i])
						break
					}
				}
				if len(result) > 0 {
					DnsRecordsCache[op_signal[0]] = result
				} else {
					delete(DnsRecordsCache, op_signal[0])
				}
			}
			continue
		}

		var list []models.DnsRecords
		if strings.HasSuffix(msg.Payload, "reload") {
			op_signal := strings.Split(msg.Payload, ":")
			if len(op_signal) != 4 {
				log.Println("从redis接收到的数据不正确，不做处理，消息内容：", msg.Payload)
				continue
			}
			clusterId, _ := strconv.ParseInt(op_signal[0], 10, 64)
			list = getDnsRecords(clusterId, op_signal[1], op_signal[2])
		}

		if strings.HasSuffix(msg.Payload, "add") {
			op_signal := strings.Split(msg.Payload, ":")
			if len(op_signal) != 7 {
				log.Println("从redis接收到的数据不正确，不做处理，消息内容：", msg.Payload)
				continue
			}
			keyname := op_signal[0] + "-" + op_signal[3] + "-" + op_signal[1]
			dnsRecords, ok := DnsRecordsCache[keyname]

			id, _ := strconv.ParseInt(op_signal[5], 10, 64)
			if ok { // 如果存在则加入列表
				isAdd := true
				for _, v := range dnsRecords {
					if v.Id == id {
						isAdd = false
					}
				}
				if isAdd {
					dnsModel := buildModelByChange(id, op_signal)
					tmpDr := buildDR(dnsModel)
					dnsRecords = append(dnsRecords, tmpDr)
					DnsRecordsCache[keyname] = dnsRecords
				} else {
					log.Println("要添加的内容已存在,不做添加", op_signal)
				}
				continue
			} else {
				dnsModel := buildModelByChange(id, op_signal)
				list = append(list, dnsModel)
			}
			if len(list) <= 0 {
				log.Println("initdnscache.go: subRedis() error: ", "缓存中已存在该记录，不做处理，消息内容：", msg.Payload)
				continue
			}
		}
		if strings.HasSuffix(msg.Payload, "update") {
			op_signal := strings.Split(msg.Payload, ":")
			if len(op_signal) != 7 {
				log.Println("从redis接收到的update数据不正确，不做处理，消息内容：", msg.Payload)
				continue
			}
			keyname := op_signal[0] + "-" + op_signal[3] + "-" + op_signal[1]
			cacheDr, ok := DnsRecordsCache[keyname]
			if ok {
				id, _ := strconv.ParseInt(op_signal[5], 10, 64)
				for i, v := range cacheDr {
					if v.Id == id {
						dnsModel := buildModelByChange(id, op_signal)
						cacheDr[i] = buildDR(dnsModel)
					}
				}
				DnsRecordsCache[keyname] = cacheDr
				continue
			} else {
				log.Println("subRedis() update error: ", "缓存中不存在该记录，不做处理，消息内容：", msg.Payload)
				continue
			}
		}

		if len(list) == 0 {
			log.Println("initdnscache.go: subRedis() error: ", "没有获取到数据，不做处理，消息内容：", msg.Payload)
			continue
		}
		buildDnsRecordsCache(list, true)
		log.Println("initdnscache.go: subRedis() success: ", "更新缓存成功", list)
		continue
	}
}

func buildModelByChange(id int64, op_signal []string) models.DnsRecords {
	qty, _ := strconv.ParseUint(op_signal[3], 10, 16)
	ttl, _ := strconv.ParseUint(op_signal[4], 10, 32)
	dnsModel := models.DnsRecords{
		ClusterName: op_signal[0],
		Name:        op_signal[1],
		Rdata:       op_signal[2],
		Qtype:       uint16(qty),
		Ttl:         uint32(ttl),
		Id:          id,
	}
	return dnsModel
}

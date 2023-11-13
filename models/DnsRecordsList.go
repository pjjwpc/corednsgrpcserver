package models

import (
	"time"
)

type DnsRecords struct {
	Id          int       `gorm:"column:id;primary_key"`
	ClusterName string    `gorm:"column:cluster_name"`
	Name        string    `gorm:"column:name"`
	Qtype       uint16    `gorm:"column:qtype"`
	Qclass      uint16    `gorm:"column:qclass"`
	Ttl         uint32    `gorm:"column:ttl"`
	Rdata       string    `gorm:"column:rdata"`
	CreateUser  string    `gorm:"column:create_user"`
	UpdateUser  string    `gorm:"column:update_user"`
	CreateTime  time.Time `gorm:"column:create_time"`
	UpdateTime  time.Time `gorm:"column:update_time"`
}

func (DnsRecords) TableName() string {
	return "dns_records"
}

package config

import (
	"log"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var Orm *gorm.DB

func initDB() {
	Orm = gormDB()
}

func gormDB() *gorm.DB {
	db, err := gorm.Open(mysql.Open(Config.DbConfig.Dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	mysqlDb, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}

	mysqlDb.SetMaxOpenConns(50)
	mysqlDb.SetConnMaxIdleTime(10)
	mysqlDb.SetConnMaxLifetime(time.Hour)
	return db
}

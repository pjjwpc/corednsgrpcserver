package config

import (
	"encoding/json"
	"log"
	"os"
	"strings"
)

// 定义配置结构体
type AppConfig struct {
	RedisConfig RedisConfig `json:"redisConfig"`
	DbConfig    DbConfig    `json:"dbConfig"`
	CacheFile   string      `json:"cacheFile"`
	IsMaster    bool        `json:"isMaster"`
}

type RedisConfig struct {
	RedisAddrs    string `json:"redisAddrs"`
	RedisPassword string `json:"redisPassword"`
	RedisDb       int    `json:"redisDb"`
	RedisPrefix   string `json:"redisPrefix"`
	RedisChannel  string `json:"redisChannel"`
}

type DbConfig struct {
	Dsn                 string `json:"dsn"`
	DbMaxOpenCon        int    `json:"dbMaxOpenCon"`
	DbMaxIdleCon        int    `json:"dbMaxIdleCon"`
	DbMaxIdleContimeout int    `json:"dbMaxIdleContimeoout"`
}

var Config AppConfig

// 定义初始化函数，读取appsetting.json配置文件，使用json.Unmarshal()函数将配置文件中的配置信息读取到结构体中
func init() {
	// 当前目录读取appsetting.json文件
	file, err := os.Open("./appsetting.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	// 读取文件内容
	decoder := json.NewDecoder(file)
	// 将文件内容解析到结构体中
	err = decoder.Decode(&Config)
	if err != nil {
		log.Fatal(err)
	}
	podIndexStr := os.Getenv("POD_NAME")
	log.Println("podIndexStr:", podIndexStr)
	isMaster := strings.HasSuffix(podIndexStr, "-0")
	if isMaster {
		log.Println("索引为0的pod为master")
		Config.IsMaster = true
	} else {
		log.Println("索引不为0的pod为slave")
		Config.IsMaster = false
	}

	initDB()
	initRedis()
}

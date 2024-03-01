package config

import (
	"github.com/redis/go-redis/v9"
)

var RedisDb *redis.Client
var RedisChannel, RedisPrefix string

func initRedis() {
	address := Config.RedisConfig.RedisAddrs
	pwd := Config.RedisConfig.RedisPassword
	db := Config.RedisConfig.RedisDb
	redis_channel := Config.RedisConfig.RedisChannel
	RedisChannel = redis_channel
	RedisDb = redis.NewClient(&redis.Options{
		Addr:     address,
		Password: pwd,
		DB:       db,
	})
}

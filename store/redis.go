package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"nirvishaai/backend/config"

	"github.com/redis/go-redis/v9"
)

var client *redis.Client
var ctx = context.Background()

const (
	TTLScanResult    = 6 * time.Hour
	TTLVerification  = 24 * time.Hour
	TTLRateLimit     = 24 * time.Hour
)

func InitRedis() error {
	opts, err := redis.ParseURL(config.App.RedisURL)
	if err != nil {
		return fmt.Errorf("invalid REDIS_URL: %w", err)
	}
	client = redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}
	return nil
}

func Close() {
	if client != nil {
		client.Close()
	}
}

func Set(key string, value any, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return client.Set(ctx, key, data, ttl).Err()
}

func Get(key string, dest any) error {
	data, err := client.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

func SetString(key, value string, ttl time.Duration) error {
	return client.Set(ctx, key, value, ttl).Err()
}

func GetString(key string) (string, error) {
	return client.Get(ctx, key).Result()
}

func Delete(key string) error {
	return client.Del(ctx, key).Err()
}

func Exists(key string) (bool, error) {
	n, err := client.Exists(ctx, key).Result()
	return n > 0, err
}

func IncrWithTTL(key string, ttl time.Duration) (int64, error) {
	pipe := client.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func ScanKey(id string) string        { return fmt.Sprintf("scan:%s", id) }
func ScanProgressKey(id string) string { return fmt.Sprintf("scan:progress:%s", id) }
func VerifyKey(domain string) string  { return fmt.Sprintf("verify:%s", domain) }
func RateLimitKey(ip string) string   { return fmt.Sprintf("ratelimit:%s", ip) }

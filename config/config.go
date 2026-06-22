package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port                string
	AllowedOrigins      string
	RedisURL            string
	OpenRouterAPIKey    string
	OpenRouterModel     string
	FallbackModels      []string
	ScanTimeout         int
	MaxConcurrentScans  int
}

var App *Config

func Load() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	scanTimeout, _ := strconv.Atoi(getEnv("SCAN_TIMEOUT", "30"))
	maxScans, _ := strconv.Atoi(getEnv("MAX_CONCURRENT_SCANS", "10"))

	App = &Config{
		Port:               getEnv("PORT", "8080"),
		AllowedOrigins:     getEnv("ALLOWED_ORIGINS", "http://localhost:3000"),
		RedisURL:           getEnv("REDIS_URL", "redis://localhost:6379"),
		OpenRouterAPIKey:   getEnv("OPENROUTER_API_KEY", ""),
		OpenRouterModel:    getEnv("OPENROUTER_MODEL", "google/gemini-flash-1.5"),
		FallbackModels: []string{
			getEnv("OPENROUTER_FALLBACK_MODEL_1", "openai/gpt-4o-mini"),
			getEnv("OPENROUTER_FALLBACK_MODEL_2", "anthropic/claude-3-haiku"),
			getEnv("OPENROUTER_FALLBACK_MODEL_3", "meta-llama/llama-3.1-8b-instruct:free"),
			getEnv("OPENROUTER_FALLBACK_MODEL_4", "mistralai/mistral-7b-instruct:free"),
		},
		ScanTimeout:        scanTimeout,
		MaxConcurrentScans: maxScans,
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

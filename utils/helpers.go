package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port           string
	DBPath         string
	JWTSecret      string
	JWTExpiryHours int
	AdminKey       string
}

func LoadConfig() *Config {
	return &Config{
		Port:           getEnv("PORT", "8080"),
		DBPath:         getEnv("DB_Path", "./auth.db"),
		JWTSecret:      getEnv("JWT_SECRET", "default_secret"),
		JWTExpiryHours: getEnvAsInt("JWT_EXPIRY_HOURS", 24),
		AdminKey:       getEnv("ADMIN_KEY", "ADMIN_KEY"),
	}
}

func (c *Config) JWTExpiry() time.Duration {
	return time.Duration(c.JWTExpiryHours) * time.Hour
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func WriteJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func SerUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, "user_id", userID)
}

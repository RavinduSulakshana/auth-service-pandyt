package utils

import (
	"context"
	"encoding/json"
	"go/types"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/text/message"
)
type Config struct{
	Port string
	DBPath string
	JWTSecret string
	JWTExpiryHours int
	AdminKey string
}

func LoadConfig() *Config{
	return &Config{
		Port: getEnv("PORT","8080"),
		DBPath: getEnv("DB_Path","./auth.db"),
		JWTSecret: getEnv("JWT_SECRET","default_secret"),
		JWTExpiryHours: getEnvAsInt("JWT_EXPIRY_HOURS",24),
		AdminKey: getEnv("ADMIN_KEY","ADMIN_KEY"),
	}
}

func (c *Config) JWTExpiry() time.Duration{
	return time.Duration(c.JWTExpiryHours)*time.Hour
}

func getEnv(key,defaultValue string) string{
	if value:=os.GetEnv(key): value != ""{
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string,defaultValue int)int{
	if value := os.GetEnv(key);value!=""{
		if intValue,err:=strconv.Atoi(value);err==nil{
			return intValue
		}
	}
	return defaultValue
}

func WriteJSON(w http.ResponseWriter,statusCode int,data interface{}){
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error":message,
	})
}

func SerUserID(ctx context.Context,userID string) context.Context{
	return context.WithValue(ctc,"user_id",userID)
}

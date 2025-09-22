package main

import (
	"log"
	"net/http"

	"github.com/RavinduSulakshana/auth-service-pandyt/auth"
	"github.com/RavinduSulakshana/auth-service-pandyt/database"
	"github.com/RavinduSulakshana/auth-service-pandyt/handlers"
	"github.com/RavinduSulakshana/auth-service-pandyt/utils"
	"github.com/ccojocar/zxcvbn-go/data"
)

func main() {
	//Load config
	config := utils.LoadConfig()

	//Initialize database
	db, err := database.New(config.DBPath)
	if err != nil {
		log.Fatal("Failed to Initialize database:", err)
	}
	defer db.Close()

	//Initialize JWT manager
	jwtManager := auth.NewJWTManager(config.JWTSecret, config.JWTExpiry())

	//Initialize Handlers
	authHandler := handlers.NewAuthHandler(db, jwtManager)
	adminHandler := handlers.NewAdminHandler(db, config.AdminKey)

	//setup routes
	mux := http.NewServeMux()

	//public routes
	mux.HandleFunc("POST /auth/signup", authHandler.SignUp)
	mux.HandleFunc("POST /auth/login", authHandler.Login)
	mux.HandleFunc("POST /auth/refresh", authHandler.RefreshToken)

	//protected routes
	mux.Handle("GET /auth/profile", authHandler.AuthMiddleware(http.HandleFunc(authHandler.Profile)))
	mux.HandleFunc("POST /auth/logout", authHandler.AuthMiddleware(http.HandleFunc(authMiddleware.Logout)))

	//Admin routes
	mux.HandleFunc("GET /admin/health", adminHandler.Health)

	// add CORS AuthMiddleware
	handler := corsMiddleware(mux)

	//start server
	addr := ":" + config.Port
	log.Printf("Server starting on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandleFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Admin-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

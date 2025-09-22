package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RavinduSulakshana/auth-service-pandyt/auth"
	"github.com/RavinduSulakshana/auth-service-pandyt/database"
	"github.com/RavinduSulakshana/auth-service-pandyt/handlers"
	"github.com/RavinduSulakshana/auth-service-pandyt/utils"
	"golang.org/x/crypto/bcrypt"
)

// setupTestServer initializes a test server with an in-memory database.
func setupTestServer() (*httptest.Server, *database.DB) {
	db, _ := database.New(":memory:")
	jwtManager := auth.NewJWTManager("test_secret", 15*time.Minute)
	authHandler := handlers.NewAuthHandler(db, jwtManager)
	adminHandler := handlers.NewAdminHandler(db, "test_admin_key")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/signup", authHandler.SignUp)
	mux.HandleFunc("POST /auth/login", authHandler.Login)
	mux.HandleFunc("POST /auth/refresh", authHandler.RefreshToken)
	mux.Handle("GET /auth/profile", authHandler.AuthMiddleware(http.HandlerFunc(authHandler.Profile)))
	mux.HandleFunc("GET /admin/health", adminHandler.Health)

	// Add a user to the database for login tests.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	db.CreateUser(&models.User{
		ID:        "test-user-id",
		Email:     "existing@example.com",
		Password:  string(hashedPassword),
		FirstName: "Existing",
		LastName:  "User",
		CreatedAt: time.Now(),
	})

	return httptest.NewServer(mux), db
}

// TestEndToEndAuthFlow tests the entire authentication process.
func TestEndToEndAuthFlow(t *testing.T) {
	ts, db := setupTestServer()
	defer ts.Close()
	defer db.Close()

	// Step 1: Sign up a new user.
	t.Run("SignUp", func(t *testing.T) {
		signupReq := `{"email": "new@example.com", "password": "Password123", "firstname": "New", "lastname": "User"}`
		resp, _ := http.Post(ts.URL+"/auth/signup", "application/json", strings.NewReader(signupReq))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("SignUp failed with status code %d", resp.StatusCode)
		}
	})

	// Step 2: Login with an existing user and get tokens.
	var accessToken, refreshToken string
	t.Run("Login", func(t *testing.T) {
		loginReq := `{"email": "existing@example.com", "password": "Password123"}`
		resp, _ := http.Post(ts.URL+"/auth/login", "application/json", strings.NewReader(loginReq))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Login failed with status code %d", resp.StatusCode)
		}
		var loginResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&loginResp)
		tokens := loginResp["tokens"].(map[string]interface{})
		accessToken = tokens["access_token"].(string)
		refreshToken = tokens["refresh_token"].(string)
	})

	// Step 3: Access a protected route with the access token.
	t.Run("Profile", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/auth/profile", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Profile access failed with status code %d", resp.StatusCode)
		}
	})

	// Step 4: Refresh tokens.
	var oldRefreshToken string
	t.Run("RefreshToken", func(t *testing.T) {
		oldRefreshToken = refreshToken
		refreshReq := `{"refresh_token": "` + oldRefreshToken + `"}`
		resp, _ := http.Post(ts.URL+"/auth/refresh", "application/json", strings.NewReader(refreshReq))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Refresh token failed with status code %d", resp.StatusCode)
		}
		var refreshResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&refreshResp)
		newTokens := refreshResp["tokens"].(map[string]interface{})
		refreshToken = newTokens["refresh_token"].(string)
	})

	// Step 5: Test that the old refresh token is now invalid (token rotation).
	t.Run("OldTokenInvalidation", func(t *testing.T) {
		invalidReq := `{"refresh_token": "` + oldRefreshToken + `"}`
		resp, _ := http.Post(ts.URL+"/auth/refresh", "application/json", strings.NewReader(invalidReq))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Old token was not invalidated. Expected %d, got %d", http.StatusUnauthorized, resp.StatusCode)
		}
	})
}

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode"

	"github.com/RavinduSulakshana/auth-service-pandyt/auth"
	"github.com/RavinduSulakshana/auth-service-pandyt/database"
	"github.com/RavinduSulakshana/auth-service-pandyt/models"
	"github.com/RavinduSulakshana/auth-service-pandyt/utils"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

type AuthHandler struct {
	db         *database.DB
	jwtManager *auth.JWTManager
}

func NewAuthHandler(db *database.DB, jwtManager *auth.JWTManager) *AuthHandler {
	return &AuthHandler{
		db:         db,
		jwtManager: jwtManager,
	}
}
func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	var hasLetter, hasDigit bool

	for _, char := range password {
		if unicode.IsLetter(char) {
			hasLetter = true
		}
		if unicode.IsDigit(char) {
			hasDigit = true
		}
		// Early return if both conditions are met
		if hasLetter && hasDigit {
			break
		}
	}

	if !hasLetter {
		return errors.New("password must contain at least one letter")
	}

	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}

	return nil
}
func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	var req models.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid Request body")
		return
	}
	// validate inputs
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		utils.WriteError(w, http.StatusBadRequest, "all fields are required")
		return
	}
	//password validation
	if err := validatePassword(req.Password); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	//chack if user exist
	existingUser, err := h.db.GetUserByEmail(req.Email)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database eroor")
		return
	}
	if existingUser != nil {
		utils.WriteError(w, http.StatusConflict, "user already exist")
		return
	}

	//hash Password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	//create user
	user := &models.User{
		ID:        uuid.New().String(),
		Email:     req.Email,
		Password:  string(hashedPassword),
		FirstName: req.FirstName,
		LastName:  req.LastName,
		CreatedAt: time.Now(),
	}
	if err := h.db.CreateUser(user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to create User")
		return
	}

	//remove password from user
	user.Password = ""
	utils.WriteJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "user created successfully",
		"user":    user,
	})
}
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid request Body")
		return
	}

	//get user
	user, err := h.db.GetUserByEmail(req.Email)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database error ")
		return
	}

	if user == nil {
		utils.WriteError(w, http.StatusUnauthorized, "invalid credential")
		return
	}

	//Check Password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "invalid credential")
		return
	}
	//Generate tokens
	tokens, err := h.generateTokens(user.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to generate tokens")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Login successfully",
		"tokens":  tokens,
	})
}
func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	user, err := h.db.GetUserByID(userID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if user == nil {
		utils.WriteError(w, http.StatusNotFound, "User not found")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"user": user,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	if err := h.db.DeleteUserTokens(userID); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to logout")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Logout successful",
	})
}

func (h *AuthHandler) generateTokens(userID string) (*models.TokenResponse, error) {
	// Generate access token
	accessToken, err := h.jwtManager.GenerateAccessToken(userID)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := h.jwtManager.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Store refresh token
	tokenRecord := &models.RefreshToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     h.jwtManager.HashToken(refreshToken),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
	}

	if err := h.db.SaveRefreshToken(tokenRecord); err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Middleware
func (h *AuthHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			utils.WriteError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			utils.WriteError(w, http.StatusUnauthorized, "Invalid authorization header")
			return
		}

		userID, err := h.jwtManager.ValidateToken(parts[1])
		if err != nil {
			utils.WriteError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		ctx := r.Context()
		ctx = utils.SetUserID(ctx, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		utils.WriteError(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	// Hash the provided token to compare with stored hash
	tokenHash := h.jwtManager.HashToken(req.RefreshToken)

	// Get the stored refresh token
	storedToken, err := h.db.GetRefreshToken(tokenHash)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	// Check if token is expired
	if time.Now().After(storedToken.ExpiresAt) {
		h.db.DeleteRefreshToken(tokenHash)
		utils.WriteError(w, http.StatusUnauthorized, "Refresh token expired")
		return
	}

	// Delete the old refresh token
	h.db.DeleteRefreshToken(tokenHash)

	// Generate new tokens
	tokens, err := h.generateTokens(storedToken.UserID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to generate tokens")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Tokens refreshed successfully",
		"tokens":  tokens,
	})
}

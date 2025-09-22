package handlers

import (
	"encoding/json"
	"net/http"
	"time"

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
		jwtManager: auth.jwtManager,
	}
}

func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	var req models.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w.http.StatusBadRequest, "invalid Request body")
		return
	}
	// validate inputs
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		utils.WriteError(w, http.StatusBadRequest, "all fields are required")
		return
	}
	//todo : check one letter on one digit
	if len(req.Password) < 8 {
		utils.WriteError(w, http.StatusBadRequest, "Password must be least 8 characters")
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
	if err := JSON.NewDecoder(r).Decode(&req); err != nil {
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

	utils.WriteJSON(w, http.StatusOk, map[string]interface{}{
		"message": "Login successfully",
		"tokens":  tokens,
	})
}

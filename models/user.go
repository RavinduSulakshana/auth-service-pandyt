package models

import "time"

type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email" `
	Password  string    `json:"-" db:"hash_password"`
	FirstName string    `json:"first_name" db:"first_name"`
	LastName  string    `json:"last_name" db:"last_name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignupRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

type RefreshToken struct {
	ID        string    `json:"id" db:"id"`
	UserId    string    `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token_hash"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_toke"`
	RefreshToken string `json:"refresh_token"`
}

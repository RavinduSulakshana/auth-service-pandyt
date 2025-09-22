package database

import (
	"database/sql"
	"github.com/RavinduSulakshana/auth-service-pandyt/models"
	_ "github.com/mattn/go-sqlite3"
	"time"
)

type DB struct {
	conn *sql.DB
}

func New(dbpath string) (*DB, error) {
	conn, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return nil, err
	}

	db := &DB{conn: conn}
	if err := db.createTables(); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *DB) createTables() error {
	userTable := `
	CREATE TABLE IF NOT EXISTS users(
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		first_name TEXT NOT NULL,
		last_name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)
	`

	tokenTable := `
	CREATE TABLE IF NOT EXISTS refresh_tokens(
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		token_hash TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES user(id)
	)
	`
	if _, err := db.conn.Exec(userTable); err != nil {
		return err
	}

	if _, err := db.conn.Exec(tokenTable); err != nil {
		return err
	}
	return nil

}
func (db *DB) CreateUser(user *models.User) error {
	query := `INSERT INTO users (id,email,password_hash,first_name,last_name)
	VALUES (?,?,?,?,?)
	`
	_, err := db.conn.Exec(query, user.ID, user.Email, user.Password, user.FirstName, user.LastName)
	return err
}

func (db *DB) GetUserByEmail(email string) (*models.User, error) {
	query := `SELECT id,email,password_hash,first_name,last_name,created_at FROM users WHERE email=?`
	user := &models.User{}

	err := db.conn.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName, &user.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	return user, err
}
func (db *DB) GetUserByID(id string) (*models.User, error) {
	query := `SELECT id,email,password_hash,first_name,last_name,created_at FROM users WHERE id=?`
	user := &models.User{}

	err := db.conn.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName, &user.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (db *DB) SaveRefreshToken(token *models.RefreshToken) error {
	query := `INSERT INTO refresh_tokens(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)`
	_, err := db.conn.Exec(query, token.ID, token.UserID, token.Token, token.ExpiresAt)

	return err
}

func (db *DB) GetRefreshToken(token_hash string) (*models.RefreshToken, error) {
	query := `SELECT id,user_id,token_hash,expires_at FROM refresh_tokens WHERE token_hash=?`

	token := &models.RefreshToken{}
	err := db.conn.QueryRow(query, token_hash).Scan(&token.ID, &token.UserID, &token.Token, &token.ExpiresAt)

	if err == sql.ErrNoRows {
		return nil, err
	}

	return token, err
}

func (db *DB) DeleteRefreshToken(token_hash string) error {
	query := `DELETE FROM refresh_tokens WHERE token_hash=?`
	_, err := db.conn.Exec(query, token_hash)

	return err
}

func (db *DB) DeleteUserToken(userId string) error {
	query := `DELETE FROM refresh_tokens WHERE user_id=?`
	_, err := db.conn.Exec(query, userId)

	return err
}

func (db *DB) Close() error {
	return db.conn.Close()
}

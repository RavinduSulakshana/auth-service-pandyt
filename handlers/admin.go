package handlers

import (
	"net/http"
	"simple-auth/database"
	"simple-auth/utils"
)

type AdminHandler struct {
	db       *database.DB
	adminKey string
}

func NewAdminHandler(db *database.DB, adminKey string) *AdminHandler {
	return &AdminHandler{
		db:       db,
		adminKey: adminKey,
	}
}

func (h *AdminHandler) Health(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-Admin-Key")
	if apiKey != h.adminKey {
		utils.WriteError(w, http.StatusUnauthorized, "Invalid apiKey")
		return
	}
	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"message": "server is running",
	})
}

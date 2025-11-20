package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// --- Configuration ---
const (
	Port   = ":8080"
	DBPath = "./cscup.db"
	WebDir = "."
)

// --- Data Structures ---

type Player struct {
	ID        int    `json:"id,omitempty"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	GradYear  string `json:"gradYear"`
	IsCaptain bool   `json:"isCaptain"`
	Phone     string `json:"phone,omitempty"`
	IsReserve bool   `json:"isReserve"`
}

type TeamRegistration struct {
	TeamName string   `json:"teamName"`
	Players  []Player `json:"players"`
}

type Team struct {
	ID           int       `json:"id"`
	Name         string    `json:"name"`
	TelegramID   int64     `json:"telegramId"`
	TelegramUser string    `json:"telegramUser"`
	Players      []Player  `json:"players"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// --- Telegram Auth Validator ---

func validateTelegramData(initData string) (int64, string, error) {
	// Parse the initData
	values, err := url.ParseQuery(initData)
	if err != nil {
		return 0, "", fmt.Errorf("failed to parse initData")
	}

	// Extract hash
	hash := values.Get("hash")
	if hash == "" {
		return 0, "", fmt.Errorf("hash not found")
	}
	values.Del("hash")

	// Create data-check-string
	var keys []string
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var dataCheckArr []string
	for _, k := range keys {
		dataCheckArr = append(dataCheckArr, fmt.Sprintf("%s=%s", k, values.Get(k)))
	}
	dataCheckString := strings.Join(dataCheckArr, "\n")

	token := os.Getenv("TELEGRAM_TOKEN")
	if token == "" {
		return 0, "", fmt.Errorf("TELEGRAM_TOKEN not set")
	}

	// Compute secret key
	secretKey := hmac.New(sha256.New, []byte("WebAppData"))
	secretKey.Write([]byte(token))

	// Compute hash
	h := hmac.New(sha256.New, secretKey.Sum(nil))
	h.Write([]byte(dataCheckString))
	calculatedHash := hex.EncodeToString(h.Sum(nil))

	// Compare hashes
	if calculatedHash != hash {
		return 0, "", fmt.Errorf("invalid hash")
	}

	// Extract user data
	userJSON := values.Get("user")
	if userJSON == "" {
		return 0, "", fmt.Errorf("user data not found")
	}

	var userData struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal([]byte(userJSON), &userData); err != nil {
		return 0, "", fmt.Errorf("failed to parse user data")
	}

	return userData.ID, userData.Username, nil
}

// --- Database Manager ---

type DBManager struct {
	db *sql.DB
	mu sync.Mutex
}

func NewDBManager(path string) (*DBManager, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// Create tables
	query := `
	CREATE TABLE IF NOT EXISTS teams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		telegram_id INTEGER NOT NULL,
		telegram_username TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS players (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		team_id INTEGER,
		first_name TEXT NOT NULL,
		last_name TEXT NOT NULL,
		grad_year TEXT NOT NULL,
		is_captain BOOLEAN DEFAULT 0,
		phone TEXT,
		is_reserve BOOLEAN DEFAULT 0,
		FOREIGN KEY(team_id) REFERENCES teams(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_teams_telegram_id ON teams(telegram_id);
	`
	_, err = db.Exec(query)
	if err != nil {
		return nil, err
	}

	return &DBManager{db: db}, nil
}

func (m *DBManager) RegisterTeam(reg TeamRegistration, telegramID int64, telegramUser string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tx, err := m.db.Begin()
	if err != nil {
		return 0, err
	}

	// Check if user already has a team
	var existingTeamID int64
	err = tx.QueryRow("SELECT id FROM teams WHERE telegram_id = ?", telegramID).Scan(&existingTeamID)
	if err == nil {
		tx.Rollback()
		return 0, fmt.Errorf("user already registered a team")
	}

	// Insert Team
	res, err := tx.Exec(
		"INSERT INTO teams (name, telegram_id, telegram_username) VALUES (?, ?, ?)",
		reg.TeamName, telegramID, telegramUser,
	)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	teamID, _ := res.LastInsertId()

	// Insert Players
	stmt, err := tx.Prepare(`
		INSERT INTO players 
		(team_id, first_name, last_name, grad_year, is_captain, phone, is_reserve) 
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer stmt.Close()

	for _, p := range reg.Players {
		_, err = stmt.Exec(
			teamID,
			p.FirstName,
			p.LastName,
			p.GradYear,
			p.IsCaptain,
			p.Phone,
			p.IsReserve,
		)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
	}

	return teamID, tx.Commit()
}

func (m *DBManager) UpdateTeam(teamID int64, reg TeamRegistration, telegramID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tx, err := m.db.Begin()
	if err != nil {
		return err
	}

	// Verify ownership
	var ownerID int64
	err = tx.QueryRow("SELECT telegram_id FROM teams WHERE id = ?", teamID).Scan(&ownerID)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("team not found")
	}
	if ownerID != telegramID {
		tx.Rollback()
		return fmt.Errorf("permission denied")
	}

	// Update team name
	_, err = tx.Exec(
		"UPDATE teams SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		reg.TeamName, teamID,
	)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Delete old players
	_, err = tx.Exec("DELETE FROM players WHERE team_id = ?", teamID)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Insert new players
	stmt, err := tx.Prepare(`
		INSERT INTO players 
		(team_id, first_name, last_name, grad_year, is_captain, phone, is_reserve) 
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, p := range reg.Players {
		_, err = stmt.Exec(
			teamID,
			p.FirstName,
			p.LastName,
			p.GradYear,
			p.IsCaptain,
			p.Phone,
			p.IsReserve,
		)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func (m *DBManager) GetTeamByTelegramID(telegramID int64) (*Team, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var team Team
	err := m.db.QueryRow(`
		SELECT id, name, telegram_id, telegram_username, created_at 
		FROM teams WHERE telegram_id = ?
	`, telegramID).Scan(
		&team.ID,
		&team.Name,
		&team.TelegramID,
		&team.TelegramUser,
		&team.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Get players
	rows, err := m.db.Query(`
		SELECT id, first_name, last_name, grad_year, is_captain, phone, is_reserve
		FROM players WHERE team_id = ? ORDER BY is_captain DESC, is_reserve ASC
	`, team.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var p Player
		err := rows.Scan(&p.ID, &p.FirstName, &p.LastName, &p.GradYear, &p.IsCaptain, &p.Phone, &p.IsReserve)
		if err != nil {
			return nil, err
		}
		team.Players = append(team.Players, p)
	}

	return &team, nil
}

func (m *DBManager) GetAllTeams() ([]Team, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rows, err := m.db.Query(`
		SELECT id, name, telegram_id, telegram_username, created_at 
		FROM teams ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var teams []Team
	for rows.Next() {
		var team Team
		err := rows.Scan(
			&team.ID,
			&team.Name,
			&team.TelegramID,
			&team.TelegramUser,
			&team.CreatedAt,
		)
		if err != nil {
			continue
		}

		// Get players for each team
		pRows, err := m.db.Query(`
			SELECT id, first_name, last_name, grad_year, is_captain, phone, is_reserve
			FROM players WHERE team_id = ? ORDER BY is_captain DESC, is_reserve ASC
		`, team.ID)
		if err != nil {
			continue
		}

		for pRows.Next() {
			var p Player
			err := pRows.Scan(&p.ID, &p.FirstName, &p.LastName, &p.GradYear, &p.IsCaptain, &p.Phone, &p.IsReserve)
			if err != nil {
				continue
			}
			team.Players = append(team.Players, p)
		}
		pRows.Close()

		teams = append(teams, team)
	}

	return teams, nil
}

// --- Handlers ---

var dbMgr *DBManager

func apiRegisterHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate Telegram auth
	initData := r.Header.Get("X-Telegram-Init-Data")
	if initData == "" {
		jsonError(w, "Unauthorized: No Telegram data", http.StatusUnauthorized)
		return
	}

	telegramID, telegramUser, err := validateTelegramData(initData)
	if err != nil {
		log.Printf("Auth error: %v", err)
		jsonError(w, "Unauthorized: Invalid Telegram data", http.StatusUnauthorized)
		return
	}

	var reg TeamRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		jsonError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validation
	if err := validateRegistration(reg); err != nil {
		jsonResponse(w, false, err.Error(), nil)
		return
	}

	// Save to DB
	teamID, err := dbMgr.RegisterTeam(reg, telegramID, telegramUser)
	if err != nil {
		log.Printf("DB Error: %v", err)
		jsonResponse(w, false, err.Error(), nil)
		return
	}

	log.Printf("Registered Team: %s (ID: %d) by @%s", reg.TeamName, teamID, telegramUser)
	jsonResponse(w, true, "Команда успешно зарегистрирована!", map[string]interface{}{
		"teamId": teamID,
	})
}

func apiUpdateHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "PUT" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate Telegram auth
	initData := r.Header.Get("X-Telegram-Init-Data")
	if initData == "" {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	telegramID, _, err := validateTelegramData(initData)
	if err != nil {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get team ID from URL
	teamIDStr := r.URL.Query().Get("id")
	teamID, err := strconv.ParseInt(teamIDStr, 10, 64)
	if err != nil {
		jsonError(w, "Invalid team ID", http.StatusBadRequest)
		return
	}

	var reg TeamRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		jsonError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validation
	if err := validateRegistration(reg); err != nil {
		jsonResponse(w, false, err.Error(), nil)
		return
	}

	// Update
	err = dbMgr.UpdateTeam(teamID, reg, telegramID)
	if err != nil {
		log.Printf("Update error: %v", err)
		jsonResponse(w, false, err.Error(), nil)
		return
	}

	log.Printf("Updated Team ID: %d", teamID)
	jsonResponse(w, true, "Команда успешно обновлена!", nil)
}

func apiMyTeamHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "GET" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate Telegram auth
	initData := r.Header.Get("X-Telegram-Init-Data")
	if initData == "" {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	telegramID, _, err := validateTelegramData(initData)
	if err != nil {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	team, err := dbMgr.GetTeamByTelegramID(telegramID)
	if err != nil {
		if err == sql.ErrNoRows {
			jsonResponse(w, true, "No team found", nil)
			return
		}
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, true, "OK", team)
}

func apiAllTeamsHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "GET" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	teams, err := dbMgr.GetAllTeams()
	if err != nil {
		jsonError(w, "Database error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, true, "OK", teams)
}

// --- Helpers ---

func validateRegistration(reg TeamRegistration) error {
	if reg.TeamName == "" {
		return fmt.Errorf("название команды обязательно")
	}
	if len(reg.Players) < 5 {
		return fmt.Errorf("необходимо минимум 5 игроков")
	}

	hasCaptain := false
	for _, p := range reg.Players {
		if p.IsCaptain {
			hasCaptain = true
			if p.Phone == "" {
				return fmt.Errorf("капитан должен указать номер телефона")
			}
		}
		if p.FirstName == "" || p.LastName == "" || p.GradYear == "" {
			return fmt.Errorf("все поля игрока обязательны")
		}
	}
	if !hasCaptain {
		return fmt.Errorf("один игрок должен быть капитаном")
	}

	return nil
}

func enableCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Telegram-Init-Data")
}

func jsonResponse(w http.ResponseWriter, success bool, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: success,
		Message: message,
		Data:    data,
	})
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{
		Success: false,
		Message: message,
	})
}

// --- Main ---

func main() {
	var err error
	dbMgr, err = NewDBManager(DBPath)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer dbMgr.db.Close()

	// Static files
	fs := http.FileServer(http.Dir(WebDir))
	http.Handle("/", fs)

	// API Endpoints
	http.HandleFunc("/api/register", apiRegisterHandler)
	http.HandleFunc("/api/update", apiUpdateHandler)
	http.HandleFunc("/api/my-team", apiMyTeamHandler)
	http.HandleFunc("/api/teams", apiAllTeamsHandler)

	fmt.Printf("🚀 CS Cup Server running on https://localhost%s\n", Port)
	fmt.Printf("📊 Database: %s\n", DBPath)
}

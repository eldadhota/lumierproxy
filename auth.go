package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"
)

// ============================================================================
// AUTHENTICATION
// ============================================================================

func generateSalt() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func hashPassword(password, salt string) string {
	hash := sha256.Sum256([]byte(password + salt))
	return hex.EncodeToString(hash[:])
}

func (s *ProxyServer) createDefaultAdmin() {
	salt := generateSalt()
	s.persistMu.Lock()
	s.persistentData.Users = append(s.persistentData.Users, UserCredentials{
		Username:     "admin",
		PasswordHash: hashPassword("admin123", salt),
		Salt:         salt,
	})
	s.persistMu.Unlock()
	go s.savePersistentData()
}

func (s *ProxyServer) validateCredentials(username, password string) bool {
	s.persistMu.RLock()
	defer s.persistMu.RUnlock()
	for _, user := range s.persistentData.Users {
		if user.Username == username {
			hash := hashPassword(password, user.Salt)
			return subtle.ConstantTimeCompare([]byte(hash), []byte(user.PasswordHash)) == 1
		}
	}
	return false
}

func (s *ProxyServer) createSession(username string) string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	token := base64.URLEncoding.EncodeToString(bytes)
	s.sessionMu.Lock()
	s.sessions[token] = &Session{
		Token:     token,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(s.persistentData.SystemSettings.SessionTimeout) * time.Hour),
	}
	s.sessionMu.Unlock()
	return token
}

func (s *ProxyServer) validateSession(token string) (*Session, bool) {
	s.sessionMu.RLock()
	session, exists := s.sessions[token]
	s.sessionMu.RUnlock()
	if !exists || time.Now().After(session.ExpiresAt) {
		if exists {
			s.sessionMu.Lock()
			delete(s.sessions, token)
			s.sessionMu.Unlock()
		}
		return nil, false
	}
	return session, true
}

func (s *ProxyServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if _, valid := s.validateSession(cookie.Value); !valid {
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func cleanupExpiredSessions() {
	for range time.NewTicker(1 * time.Hour).C {
		server.sessionMu.Lock()
		now := time.Now()
		for token, session := range server.sessions {
			if now.After(session.ExpiresAt) {
				delete(server.sessions, token)
			}
		}
		server.sessionMu.Unlock()
	}
}

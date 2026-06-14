//go:build saas

package apiserver

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// wafHandler is satisfied by *sekhem.WAFShield.
// Keeping this as a local interface prevents the circular import:
//
//	pkg/apiserver → pkg/sekhem → pkg/agi → (no pkg/apiserver).
type wafHandler interface {
	GinHandler() gin.HandlerFunc
}

// AuthMiddleware validates API key authentication
func (s *Server) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Missing Authorization header",
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		// Expected format: "Bearer <api_key>" or "Bearer <machine_id>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Invalid Authorization header format",
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		apiKey := parts[1]

		// Validate API key via LicenseManager (supports machine_id and issued API tokens)
		if s.licMgr != nil {
			valid, err := s.licMgr.ValidateAPIKey(apiKey)
			if err != nil || !valid {
				c.JSON(http.StatusUnauthorized, ErrorResponse{
					Error:   "unauthorized",
					Message: "Invalid or expired API key",
					Code:    http.StatusUnauthorized,
				})
				c.Abort()
				return
			}
		}

		// Store API key in context for later use
		c.Set("api_key", apiKey)
		c.Next()
	}
}

// CORSMiddleware handles CORS headers including Chrome's Private Network Access (PNA).
//
// Chrome 94+ enforces PNA: a page served from a secure public origin (e.g.
// https://docs.nouchix.com) is blocked from fetching localhost unless the
// local server responds to the preflight with Access-Control-Allow-Private-Network: true.
// Without this header the browser never sends the real request — it looks identical
// to ECONNREFUSED from JS, making it hard to diagnose.
//
// allowedOrigins is typically populated from Config.AllowedOrigins; the function
// also merges a set of hardcoded NouchiX / ASAF origins so local binaries work
// without any environment configuration.
func CORSMiddleware(allowedOrigins ...string) gin.HandlerFunc {
	allowed := map[string]bool{
		// NouchiX production origins — always allowed regardless of config
		"https://docs.nouchix.com":        true,
		"https://nouchix.com":             true,
		"https://www.nouchix.com":         true,
		"https://adinkhepra.com":          true,
		"https://www.adinkhepra.com":      true,
		"https://adinkhepra.dev":          true,
		"https://souhimbou.ai":            true,
		"https://souhimbou.ai":           true,
		"https://www.souhimbou.ai":       true,
		"https://gateway.souhimbou.ai":   true,
		"https://telemetry.souhimbou.ai": true,
		// Local development — serve-nlp (7777), Vite/Next (3000/5173), generic (8080)
		"http://localhost:3000":           true,
		"http://localhost:5173":           true,
		"http://localhost:7777":           true,
		"http://localhost:8080":           true,
	}
	// Merge any extra origins passed from Config.AllowedOrigins
	for _, o := range allowedOrigins {
		if o != "" {
			allowed[o] = true
		}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if allowed[origin] {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		}

		// ── Chrome Private Network Access (PNA) ───────────────────────────────
		// When a page at a public HTTPS origin fetches localhost, Chrome sends a
		// CORS preflight with "Access-Control-Request-Private-Network: true".
		// The local server MUST echo the allow header or the fetch is silently
		// blocked — the browser reports it as a CORS error, not a network error.
		if c.Request.Header.Get("Access-Control-Request-Private-Network") == "true" {
			c.Writer.Header().Set("Access-Control-Allow-Private-Network", "true")
		}

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// LoggingMiddleware logs all API requests
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		if raw != "" {
			path = path + "?" + raw
		}

		log.Printf("[API] %s %s %d %v %s",
			method,
			path,
			statusCode,
			latency,
			clientIP,
		)
	}
}

// RateLimitMiddleware implements rate limiting with safe concurrent access.
// This middleware is the pre-WAF stopgap; it is superseded by SEKHEM-007 once
// WAFShield is wired into setupMiddleware. The sync.Mutex + cleanup goroutine
// fixes the data race present in the original plain-map implementation.
func RateLimitMiddleware() gin.HandlerFunc {
	type clientInfo struct {
		lastRequest time.Time
		requests    int
	}

	const (
		maxRequests = 100
		timeWindow  = 1 * time.Minute
		cleanupEvery = 5 * time.Minute
	)

	var mu sync.Mutex
	clients := make(map[string]*clientInfo)

	// Background goroutine evicts entries idle for >2× the window so the map
	// does not grow unboundedly over long uptimes.
	go func() {
		ticker := time.NewTicker(cleanupEvery)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-2 * timeWindow)
			mu.Lock()
			for ip, c := range clients {
				if c.lastRequest.Before(cutoff) {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()

		mu.Lock()
		client, exists := clients[clientIP]
		if !exists {
			clients[clientIP] = &clientInfo{lastRequest: now, requests: 1}
			mu.Unlock()
			c.Next()
			return
		}

		if now.Sub(client.lastRequest) > timeWindow {
			client.lastRequest = now
			client.requests = 1
			mu.Unlock()
			c.Next()
			return
		}

		if client.requests >= maxRequests {
			mu.Unlock()
			c.JSON(http.StatusTooManyRequests, ErrorResponse{
				Error:   "rate_limit_exceeded",
				Message: "Too many requests, please try again later",
				Code:    http.StatusTooManyRequests,
			})
			c.Abort()
			return
		}

		client.requests++
		mu.Unlock()
		c.Next()
	}
}

// WAFMiddleware wraps the SEKHEM WAFShield as a Gin handler.
//
// Correct ordering in setupMiddleware:
//
//	RecoveryMiddleware → LoggingMiddleware → CORSMiddleware → WAFMiddleware → AuthMiddleware
//
// WAF must come AFTER CORS so OPTIONS preflights receive CORS headers before
// the WAF can block them. It must come BEFORE AuthMiddleware so un-authed
// attack traffic is rejected at the perimeter.
//
// When shield is nil the middleware is a no-op (safe for tests or environments
// where SEKHEM is not yet wired).
func WAFMiddleware(shield wafHandler) gin.HandlerFunc {
	if shield == nil {
		log.Println("[SEKHEM-WAF] WAFMiddleware: shield is nil — L7 inspection DISABLED")
		return func(c *gin.Context) { c.Next() }
	}
	return shield.GinHandler()
}

// RecoveryMiddleware recovers from panics and logs them
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC] %v", err)
				c.JSON(http.StatusInternalServerError, ErrorResponse{
					Error:   "internal_server_error",
					Message: "An unexpected error occurred",
					Code:    http.StatusInternalServerError,
				})
				c.Abort()
			}
		}()
		c.Next()
	}
}

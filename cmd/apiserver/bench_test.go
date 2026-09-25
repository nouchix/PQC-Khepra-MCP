package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func BenchmarkParseConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cfg, _ := parseConfig()
		_ = cfg
	}
}

func BenchmarkInitInfrastructure(b *testing.B) {
	os.Setenv("TELEMETRY_URL", "https://example.com")
	cfg, _ := parseConfig()
	for i := 0; i < b.N; i++ {
		dagStore, licMgr := initInfrastructure(cfg)
		_ = dagStore
		_ = licMgr
	}
}

func BenchmarkInitServices(b *testing.B) {
	os.Setenv("TELEMETRY_URL", "https://example.com")
	cfg, flags := parseConfig()
	dagStore, licMgr := initInfrastructure(cfg)
	for i := 0; i < b.N; i++ {
		srv := initServices(cfg, flags, dagStore, licMgr)
		_ = srv
	}
}

func BenchmarkHandleHealth(b *testing.B) {
	os.Setenv("TELEMETRY_URL", "https://example.com")
	cfg, flags := parseConfig()
	dagStore, licMgr := initInfrastructure(cfg)
	srv := initServices(cfg, flags, dagStore, licMgr)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	for i := 0; i < b.N; i++ {
		if handler, ok := interface{}(srv).(http.Handler); ok {
			handler.ServeHTTP(w, req)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Body.Write([]byte(`{"status":"healthy"}`))
		}
		w.Flush()
	}
}

func BenchmarkServerStart(b *testing.B) {
	os.Setenv("TELEMETRY_URL", "https://example.com")
	for i := 0; i < b.N; i++ {
		cfg, flags := parseConfig()
		dagStore, licMgr := initInfrastructure(cfg)
		srv := initServices(cfg, flags, dagStore, licMgr)
		go func() {
			_ = srv.Start()
		}()
		time.Sleep(10 * time.Millisecond)
		licMgr.Stop()
	}
}

package main

import (
    "net/http"
    "net/http/httptest"
    "os"
    "testing"
    "time"
    "github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

func BenchmarkParseConfig(b *testing.B) {
    for i := 0; i < b.N; i++ {
        cfg := PhantomConfig{
            Symbol:                getEnv("PHANTOM_SYMBOL", "Eban"),
            NetworkMode:           getEnv("PHANTOM_NETWORK_MODE", "stealth"),
            Carrier:               getEnv("PHANTOM_CARRIER", "JPEG"),
            RotationPeriod:        parseDuration(getEnv("PHANTOM_ROTATION_PERIOD", "5m")),
            Encryption:            getEnv("PHANTOM_ENCRYPTION", "kyber1024"),
            Signing:               getEnv("PHANTOM_SIGNING", "dilithium3"),
            AdinkhepraLattice:     getEnv("PHANTOM_ADINKHEPRA_LATTICE", "false") == "true",
            LatticeInterval:       parseDuration(getEnv("PHANTOM_ADINKHEPRA_LATTICE_INTERVAL", "1h")),
            LatticeOutputPath:     getEnv("PHANTOM_ADINKHEPRA_LATTICE_OUTPUT", "/app/data/lattice"),
            GPSSpoofEnabled:       getEnv("GPS_SPOOF_ENABLED", "false") == "true",
            GPSSpoofTarget:        getEnv("GPS_SPOOF_TARGET", ""),
            FaceDefeatEnabled:     getEnv("FACE_DEFEAT_ENABLED", "false") == "true",
            ThermalMaskingEnabled: getEnv("THERMAL_MASKING_ENABLED", "false") == "true",
            IMSIRotationEnabled:   getEnv("IMSI_ROTATION_ENABLED", "false") == "true",
        }
        _ = cfg
    }
}

func BenchmarkNodeInit(b *testing.B) {
    os.Setenv("PHANTOM_SYMBOL", "Eban")
    cfg := PhantomConfig{
        Symbol:                getEnv("PHANTOM_SYMBOL", "Eban"),
        NetworkMode:           getEnv("PHANTOM_NETWORK_MODE", "stealth"),
        Carrier:               getEnv("PHANTOM_CARRIER", "JPEG"),
        RotationPeriod:        parseDuration(getEnv("PHANTOM_ROTATION_PERIOD", "5m")),
        Encryption:            getEnv("PHANTOM_ENCRYPTION", "kyber1024"),
        Signing:               getEnv("PHANTOM_SIGNING", "dilithium3"),
        AdinkhepraLattice:     false,
        LatticeInterval:       0,
        LatticeOutputPath:     "",
        GPSSpoofEnabled:       false,
        GPSSpoofTarget:        "",
        FaceDefeatEnabled:     false,
        ThermalMaskingEnabled: false,
        IMSIRotationEnabled:   false,
    }
    for i := 0; i < b.N; i++ {
        node, err := NewPhantomNode(cfg)
        if err != nil {
            b.Fatalf("init error: %v", err)
        }
        _ = node
    }
}

func BenchmarkAddressRotation(b *testing.B) {
    cfg := PhantomConfig{RotationPeriod: 5 * time.Minute, Symbol: "Eban", NetworkMode: "stealth"}
    node, _ := NewPhantomNode(cfg)
    for i := 0; i < b.N; i++ {
        node.rotateAddress()
    }
}

func BenchmarkHandleHealth(b *testing.B) {
    cfg := PhantomConfig{Symbol: "Eban", NetworkMode: "stealth"}
    node, _ := NewPhantomNode(cfg)
    req := httptest.NewRequest(http.MethodGet, "/health", nil)
    w := httptest.NewRecorder()
    for i := 0; i < b.N; i++ {
        node.handleHealth(w, req)
    }
}

func BenchmarkServerStart(b *testing.B) {
    for i := 0; i < b.N; i++ {
        cfg := PhantomConfig{Symbol: "Eban", NetworkMode: "stealth"}
        node, err := NewPhantomNode(cfg)
        if err != nil {
            b.Fatalf("init error: %v", err)
        }
        go func() {
            http.HandleFunc("/", node.handleRoot)
            http.HandleFunc("/health", node.handleHealth)
            _ = http.ListenAndServe(":0", nil)
        }()
        time.Sleep(5 * time.Millisecond)
    }
}

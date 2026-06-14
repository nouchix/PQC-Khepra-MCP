package util

import (
	"os"
	"testing"
)

func TestHomeDir(t *testing.T) {
	home := HomeDir()
	if home == "" {
		t.Error("HomeDir returned empty string")
	}
}

func TestSHA256Hex(t *testing.T) {
	input := []byte("test")
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	result := SHA256Hex(input)
	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestWriteJSON(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test_json_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	data := map[string]string{"key": "value"}
	if err := WriteJSON(tmpfile.Name(), data); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	content, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if len(content) == 0 {
		t.Error("File is empty")
	}
}

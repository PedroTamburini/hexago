package handler

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestHealthReportsOK(t *testing.T) {
	engine := newTestGin()
	engine.GET("/health", Health)

	rec := performRequest(engine, jsonRequest(http.MethodGet, "/health", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	if body["status"] != "ok" {
		t.Fatalf("body = %v, want status ok", body)
	}
}

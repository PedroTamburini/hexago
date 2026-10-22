package tokenstore

import (
	"context"
	"testing"
)

func TestTokenVersionStartsAtZeroAndIncrements(t *testing.T) {
	client, _ := newTestClient(t)
	versions := NewTokenVersionManager(client)
	ctx := context.Background()

	version, err := versions.GetVersion(ctx, 7)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if version != 0 {
		t.Fatalf("GetVersion = %d, want 0", version)
	}

	version, err = versions.IncrementVersion(ctx, 7)
	if err != nil {
		t.Fatalf("IncrementVersion: %v", err)
	}
	if version != 1 {
		t.Fatalf("IncrementVersion = %d, want 1", version)
	}

	version, err = versions.GetVersion(ctx, 7)
	if err != nil {
		t.Fatalf("GetVersion after increment: %v", err)
	}
	if version != 1 {
		t.Fatalf("GetVersion after increment = %d, want 1", version)
	}
}

func TestTokenVersionIsPerUser(t *testing.T) {
	client, _ := newTestClient(t)
	versions := NewTokenVersionManager(client)
	ctx := context.Background()

	if _, err := versions.IncrementVersion(ctx, 1); err != nil {
		t.Fatalf("IncrementVersion: %v", err)
	}

	version, err := versions.GetVersion(ctx, 2)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if version != 0 {
		t.Fatalf("GetVersion for another user = %d, want 0", version)
	}
}

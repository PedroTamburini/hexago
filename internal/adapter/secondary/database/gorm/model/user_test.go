package model

import (
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

// The username and the email must only be unique among the accounts that were
// not removed. A full unique index keeps the identity of a deleted account
// reserved forever, so the indexes are asserted here to stay partial.
func TestUserModelDeclaresPartialUniqueIndexes(t *testing.T) {
	parsed, err := schema.Parse(&UserModel{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("failed to parse the user schema: %v", err)
	}

	indexes := []struct {
		name   string
		column string
	}{
		{name: "uniq_user_username", column: "username"},
		{name: "uniq_user_email", column: "email"},
	}

	for _, tc := range indexes {
		index := parsed.LookIndex(tc.name)
		if index == nil {
			t.Fatalf("expected the schema to declare the %q index", tc.name)
		}

		if index.Class != "UNIQUE" {
			t.Fatalf("index %q class = %q, want %q", tc.name, index.Class, "UNIQUE")
		}

		if index.Where != "deleted_at IS NULL" {
			t.Fatalf("index %q where = %q, want %q", tc.name, index.Where, "deleted_at IS NULL")
		}

		if len(index.Fields) != 1 {
			t.Fatalf("index %q covers %d fields, want 1", tc.name, len(index.Fields))
		}

		if index.Fields[0].DBName != tc.column {
			t.Fatalf("index %q covers the column %q, want %q", tc.name, index.Fields[0].DBName, tc.column)
		}
	}
}

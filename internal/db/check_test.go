package db

import (
	"path/filepath"
	"testing"
)

func TestInitCreatesSchemaInConfiguredDatabase(t *testing.T) {
	previousDB := DB
	t.Cleanup(func() {
		if DB != nil && DB != previousDB {
			if sqlDB, err := DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}
		DB = previousDB
	})

	dbPath := filepath.Join(t.TempDir(), "vohive.db")
	if err := Init(dbPath); err != nil {
		t.Fatalf("Init(%q): %v", dbPath, err)
	}
	if DB == nil {
		t.Fatal("Init() left DB nil")
	}
	if !DB.Migrator().HasTable(&Device{}) {
		t.Fatal("Init() did not create the devices table")
	}
}

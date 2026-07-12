package db

import (
	"fmt"
	"testing"
)

func TestCheckSchema(t *testing.T) {
	Init("/root/.gemini/antigravity/vohive.db")
	var m []map[string]interface{}
	DB.Raw("PRAGMA table_info(managed_devices)").Scan(&m)
	for _, row := range m {
		fmt.Println(row["name"])
	}
}

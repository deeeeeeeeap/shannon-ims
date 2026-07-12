package db

import (
	"fmt"
	"strings"

	glebarezSqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func openSQLiteDialector(driverName, dsn string) (gorm.Dialector, error) {
	name := strings.ToLower(strings.TrimSpace(driverName))
	switch name {
	case "", "modernc", "purego", "go", "glebarez":
		return glebarezSqlite.Open(dsn), nil
	case "cgo", "mattn":
		return nil, fmt.Errorf("cgo sqlite driver disabled")
	default:
		return nil, fmt.Errorf("unknown sqlite driver: %s", driverName)
	}
}

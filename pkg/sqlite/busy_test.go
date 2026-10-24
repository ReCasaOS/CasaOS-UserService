package sqlite

import "testing"

// a second process on the same file (-ru beside the running service) waits for its write
func TestTheDatabaseWaitsForAWriteOfAnotherProcess(t *testing.T) {
	previous := gdb
	gdb = nil
	t.Cleanup(func() { gdb = previous })
	db := GetDb(t.TempDir())
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close() // the directory is removed after: Windows cannot while the file is open
		}
	})
	var timeout int
	if err := db.Raw("PRAGMA busy_timeout").Scan(&timeout).Error; err != nil {
		t.Fatal(err)
	}
	if timeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000", timeout)
	}
}

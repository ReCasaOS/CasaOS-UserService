package service

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
)

func TestTheSigningKeyOutlivesARestart(t *testing.T) {
	logger.LogInitConsoleOnly()
	path := filepath.Join(t.TempDir(), "db", KeyFilename)

	first, _, err := loadOrCreateKeyPair(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("the key is root's alone: mode %o", info.Mode().Perm())
		}
	}

	// the next start
	second, public, err := loadOrCreateKeyPair(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.D.Cmp(first.D) != 0 || public.X.Cmp(first.PublicKey.X) != 0 {
		t.Fatal("a restart must sign with the key it signed with before")
	}
}

func TestAKeyThatCannotBeReadIsReplacedNotFatal(t *testing.T) {
	logger.LogInitConsoleOnly()
	path := filepath.Join(t.TempDir(), KeyFilename)
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	private, _, err := loadOrCreateKeyPair(path)
	if err != nil || private == nil {
		t.Fatalf("a new key, not a dead service: %v", err)
	}

	again, _, err := loadOrCreateKeyPair(path)
	if err != nil || again.D.Cmp(private.D) != 0 {
		t.Fatal("and the new key is the one on disk now")
	}
}

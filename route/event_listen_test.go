package route

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"golang.org/x/net/websocket"
)

func TestDialMessageBusSendsInternalSecretWhenPresent(t *testing.T) {
	authorizations := make(chan string, 2)
	server := httptest.NewServer(websocket.Server{
		Handshake: func(_ *websocket.Config, r *http.Request) error {
			authorizations <- r.Header.Get("Authorization")
			return nil
		},
		Handler: func(*websocket.Conn) {},
	})
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/event/local-storage"
	runtimePath := t.TempDir()

	dial := func() string {
		t.Helper()
		ws, err := dialMessageBus(wsURL, runtimePath)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		ws.Close()
		return <-authorizations
	}

	// Older gateway: no secret file, no header.
	if got := dial(); got != "" {
		t.Fatalf("Authorization without a secret file = %q, want none", got)
	}

	if err := os.WriteFile(filepath.Join(runtimePath, external.InternalSecretFilename), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, want := dial(), "Internal s3cret"; got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

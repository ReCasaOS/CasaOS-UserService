package route

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"golang.org/x/net/websocket"
)

// A dropped subscription is dialled again with the secret of the moment, and
// the listener gives up once the bus address is gone.
func TestEventListenReconnectsWithCurrentSecret(t *testing.T) {
	logger.LogInitConsoleOnly()

	authorizations := make(chan string, 4)
	proceed := make(chan struct{})
	server := httptest.NewServer(websocket.Server{
		Handshake: func(_ *websocket.Config, r *http.Request) error {
			authorizations <- r.Header.Get("Authorization")
			<-proceed
			return nil
		},
		Handler: func(*websocket.Conn) {}, // drops the subscription at once
	})
	defer server.Close()
	defer close(proceed) // runs first: a failed test does not leave a handshake blocking Close

	runtimePath := t.TempDir()
	writeFile := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(runtimePath, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(external.MessageBusAddressFilename, server.URL)
	writeFile(external.InternalSecretFilename, "first\n")

	defer func(old string) { config.CommonInfo.RuntimePath = old }(config.CommonInfo.RuntimePath)
	config.CommonInfo.RuntimePath = runtimePath

	done := make(chan struct{})
	go func() { EventListen(); close(done) }()
	handshake := func() string {
		t.Helper()
		select {
		case got := <-authorizations:
			return got
		case <-done:
			t.Fatal("EventListen returned before dialling")
		case <-time.After(10 * time.Second):
			t.Fatal("no handshake")
		}
		return ""
	}

	if got := handshake(); got != "Internal first" {
		t.Fatalf("first handshake Authorization = %q", got)
	}
	writeFile(external.InternalSecretFilename, "second\n") // the gateway restarted
	proceed <- struct{}{}

	if got := handshake(); got != "Internal second" {
		t.Fatalf("second handshake Authorization = %q", got)
	}
	if err := os.Remove(filepath.Join(runtimePath, external.MessageBusAddressFilename)); err != nil {
		t.Fatal(err)
	}
	proceed <- struct{}{}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("EventListen did not return once the bus address was gone")
	}
}

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

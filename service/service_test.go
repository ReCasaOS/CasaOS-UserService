package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
)

// TestMessageBusSendsTheInternalSecret: the message bus refuses loopback
// calls that lack the per-boot internal secret, so its client must add it.
func TestMessageBusSendsTheInternalSecret(t *testing.T) {
	var got string
	bus := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer bus.Close()

	dir := t.TempDir()
	for name, content := range map[string]string{
		external.MessageBusAddressFilename: bus.URL,
		external.InternalSecretFilename:    "s3cret",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	defer func(old string) { config.CommonInfo.RuntimePath = old }(config.CommonInfo.RuntimePath)
	config.CommonInfo.RuntimePath = dir

	resp, err := (&store{}).MessageBus().RegisterEventTypes(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !external.IsInternalRequest("127.0.0.1", got, dir) {
		t.Fatalf("the bus got Authorization %q, not the internal secret", got)
	}
}

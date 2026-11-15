package route_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The routes that take a file or a body to keep refuse one past 10 MB instead of reading it all.
func TestBodiesPastTheLimitAreRefused(t *testing.T) {
	a := newAccounts(t)
	big := strings.Repeat("a", 11<<20)
	for _, r := range []struct{ method, path, contentType string }{
		{"POST", "/v1/users/current/custom/settings", "application/json"},
		{"PUT", "/v1/users/avatar", "application/json"},
		{"PUT", "/v1/users/current/image/wall", "application/json"},
		{"POST", "/v1/users/current/image/wall", "multipart/form-data; boundary=x"},
	} {
		req := httptest.NewRequest(r.method, r.path, strings.NewReader(big))
		req.Header.Set("Content-Type", r.contentType)
		req.Header.Set("X-Real-IP", "10.0.0.1")
		req.Header.Set("Authorization", a.access)
		rec := httptest.NewRecorder()
		a.c.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s %s with 11 MB: %d, want 413", r.method, r.path, rec.Code)
		}
	}
	// and the service still answers
	a.c.expect(200, 200, "GET", "/v1/users/current", a.access, nil)
}

// The same without a Content-Length (a chunked body): the read stops at the limit and nothing is kept.
func TestBodiesPastTheLimitWithoutALengthAreRefused(t *testing.T) {
	a := newAccounts(t)
	big := strings.Repeat("a", 11<<20)
	for _, r := range []struct{ method, path, contentType string }{
		{"POST", "/v1/users/current/custom/settings", "application/json"},
		{"PUT", "/v1/users/avatar", "application/json"},
		{"PUT", "/v1/users/current/image/wall", "application/json"},
		{"POST", "/v1/users/current/image/wall", "multipart/form-data; boundary=x"},
	} {
		req := httptest.NewRequest(r.method, r.path, io.NopCloser(strings.NewReader(big)))
		req.ContentLength = -1
		req.Header.Set("Content-Type", r.contentType)
		req.Header.Set("X-Real-IP", "10.0.0.1")
		req.Header.Set("Authorization", a.access)
		rec := httptest.NewRecorder()
		a.c.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s with 11 MB and no length: %d, want 413 or 400", r.method, r.path, rec.Code)
		}
	}
	if _, err := os.Stat(filepath.Join(ownFolder(t, a.owner.Id), "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("a cut body was kept: %v", err)
	}
	a.c.expect(200, 200, "GET", "/v1/users/current", a.access, nil)
}

// A tiny picture that says it is huge is refused from its header, before any pixel is made.
func TestAnAvatarDeclaringHugeDimensionsIsRefusedFromItsHeader(t *testing.T) {
	a := newAccounts(t)
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b[16:], 20000) // IHDR width
	binary.BigEndian.PutUint32(b[20:], 20000) // IHDR height
	binary.BigEndian.PutUint32(b[29:], crc32.ChecksumIEEE(b[12:29]))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	status, _ := a.c.do("PUT", "/v1/users/avatar", a.access, map[string]string{"file": "data:image/png;base64," + base64.StdEncoding.EncodeToString(b)})
	runtime.ReadMemStats(&after)
	if status != http.StatusBadRequest {
		t.Fatalf("a 20000x20000 header: %d, want 400", status)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 64<<20 {
		t.Fatalf("the refusal allocated %d MB", grown>>20)
	}
}

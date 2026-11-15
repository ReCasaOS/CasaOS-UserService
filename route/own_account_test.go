package route_test

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
)

func ownFolder(t *testing.T, id int) string {
	t.Helper()
	dir := filepath.Join(config.AppInfo.UserDataPath, strconv.Itoa(id))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pngBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPutCurrentIgnoresFieldsOfTheRowItDoesNotOwn(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	before := a.users.GetUserAllInfoById(strconv.Itoa(id))

	a.c.expect(200, 200, "PUT", "/v1/users/current", access, map[string]interface{}{
		"avatar": "/etc/hostname", "username": "", "role": "admin", "id": a.owner.Id,
		"password": "x", "salt": "y", "totp_secret": "z", "totp_enabled": true, "totp_last_step": 9,
		"nickname": "Marie",
	})

	got := a.users.GetUserAllInfoById(strconv.Itoa(id))
	if got.Avatar != before.Avatar || got.Username != "marie" || got.Role != "user" || got.Password != before.Password ||
		got.TotpSecret != "" || got.TotpEnabled || got.TotpLastStep != 0 || got.SessionVersion != before.SessionVersion {
		t.Fatalf("the row after the save: %+v", got)
	}
	if got.Nickname != "Marie" {
		t.Fatalf("nickname %q", got.Nickname)
	}
	if other := a.users.GetUserAllInfoById(strconv.Itoa(a.owner.Id)); other.Nickname == "Marie" || other.Password == "x" {
		t.Fatalf("the owner's row: %+v", other)
	}
}

func (a accounts) get(path, token string) (int, string) {
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	a.c.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestAvatarServedOnlyFromOwnFolder(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "outside.txt")
	writeFile(t, outside, "outside-content")
	own := ownFolder(t, id)
	inside := filepath.Join(own, "avatar.png")
	writeFile(t, inside, "inside-content")

	a.users.UpdateUser(model2.UserDBModel{Id: id, Avatar: outside})
	if _, body := a.get("/v1/users/avatar", access); strings.Contains(body, "outside-content") {
		t.Fatal("a file outside the folder was served as the avatar")
	}
	// a path that leaves the folder after starting in it
	rel, err := filepath.Rel(own, outside)
	if err != nil {
		t.Fatal(err)
	}
	a.users.UpdateUser(model2.UserDBModel{Id: id, Avatar: own + "/" + filepath.ToSlash(rel)})
	if _, body := a.get("/v1/users/avatar", access); strings.Contains(body, "outside-content") {
		t.Fatal("a path leaving the folder was served as the avatar")
	}

	a.users.UpdateUser(model2.UserDBModel{Id: id, Avatar: inside})
	if status, body := a.get("/v1/users/avatar", access); status != 200 || body != "inside-content" {
		t.Fatalf("the avatar of the folder: %d %q", status, body)
	}
}

func TestDeleteImageRefusesOutsideOwnFolder(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	if id != 2 {
		t.Fatalf("id %d, want 2", id)
	}
	own := ownFolder(t, id)
	db := filepath.Join(config.AppInfo.UserDataPath, "db", "user.db")
	writeFile(t, db, "database")
	other := filepath.Join(config.AppInfo.UserDataPath, "20", "x.png")
	writeFile(t, other, "other")
	mine := filepath.Join(own, "wall.png")
	writeFile(t, mine, "mine")

	del := func(p string) int {
		status, _ := a.c.do("DELETE", "/v1/users/current/image?path="+url.QueryEscape(p), access, nil)
		return status
	}
	if got := del(own + "/../db/user.db"); got != 403 {
		t.Fatalf("a path going out: %d, want 403", got)
	}
	if got := del(other); got != 403 {
		t.Fatalf("the folder of another account: %d, want 403", got)
	}
	for _, p := range []string{db, other} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if got := del(mine); got != 200 {
		t.Fatalf("a file of the folder: %d, want 200", got)
	}
	if _, err := os.Stat(mine); !os.IsNotExist(err) {
		t.Fatalf("the file is still there: %v", err)
	}
}

func TestPutAvatarWithBrokenImageIs400(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")

	if status, _ := a.c.do("PUT", "/v1/users/avatar", access, map[string]string{"file": "AAAA"}); status != http.StatusBadRequest {
		t.Fatalf("a body that is not an image: %d, want 400", status)
	}
	if status, _ := a.c.do("PUT", "/v1/users/avatar", access, map[string]string{"file": "not base64 !"}); status != http.StatusBadRequest {
		t.Fatalf("a body that is not base64: %d, want 400", status)
	}

	a.c.expect(200, 200, "PUT", "/v1/users/avatar", access, map[string]string{"file": "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes(t))})
	want := config.AppInfo.UserDataPath + "/" + strconv.Itoa(id) + "/avatar.png"
	if got := a.users.GetUserInfoById(strconv.Itoa(id)).Avatar; got != want {
		t.Fatalf("avatar %q, want %q", got, want)
	}
}

func TestUserSeesOnlyOwnRow(t *testing.T) {
	a := newAccounts(t)
	_, access, _ := a.createUser(t, "marie")

	for _, path := range []string{"/v1/users/name", "/v1/users/owner", "/v1/users/marie"} {
		if status, _ := a.c.do("GET", path, access, nil); status != http.StatusForbidden {
			t.Fatalf("%s as a user: %d, want 403", path, status)
		}
		if status, _ := a.c.do("GET", path, a.access, nil); status != http.StatusOK {
			t.Fatalf("%s as the admin: %d, want 200", path, status)
		}
	}
	a.c.expect(200, 200, "GET", "/v1/users/current", access, nil)
}

func TestImageCopyStaysInOwnFolder(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	own := ownFolder(t, id)
	outside := filepath.Join(t.TempDir(), "pic.png")
	writeFile(t, outside, string(pngBytes(t)))
	otherAccount := filepath.Join(config.AppInfo.UserDataPath, "20", "pic.png")
	writeFile(t, otherAccount, string(pngBytes(t)))
	inside := filepath.Join(own, "source.png")
	writeFile(t, inside, string(pngBytes(t)))

	for _, src := range []string{outside, otherAccount, own + "/../20/pic.png"} {
		if status, _ := a.c.do("PUT", "/v1/users/current/image/wall", access, map[string]string{"path": src}); status != http.StatusForbidden {
			t.Fatalf("source %s: %d, want 403", src, status)
		}
	}
	if _, err := os.Stat(filepath.Join(own, "wall.png")); err == nil {
		t.Fatal("a refused copy left a file")
	}

	a.c.expect(200, 200, "PUT", "/v1/users/current/image/wall", access, map[string]string{"path": inside})
	if _, err := os.Stat(filepath.Join(own, "wall.png")); err != nil {
		t.Fatalf("the copy of a file of the folder: %v", err)
	}
}

// A delete that waited for the lock is for the account it read, not for whoever has the number now.
func TestDeleteAccountRechecksTargetUnderLock(t *testing.T) {
	a := newAccounts(t)
	a.appManagement(t, 200, nil)
	id, _, _ := a.createUser(t, "marie")

	service.UserRegisterMu.Lock()
	done := make(chan int)
	go func() {
		status, _ := a.c.do("DELETE", "/v1/users/"+strconv.Itoa(id), a.access, nil)
		done <- status
	}()
	time.Sleep(300 * time.Millisecond) // the request has read its target and waits for the lock
	if err := a.users.DeleteUserById(strconv.Itoa(id)); err != nil {
		t.Fatal(err)
	}
	// a database of before the counter may give the number again
	if err := a.db.Create(&model2.UserDBModel{Id: id, Username: "paul", Password: "x", Role: "user", SessionVersion: time.Now().UnixNano()}).Error; err != nil {
		t.Fatal(err)
	}
	service.UserRegisterMu.Unlock()

	if status := <-done; status != http.StatusNotFound {
		t.Fatalf("the late delete: %d, want 404", status)
	}
	if a.users.GetUserAllInfoById(strconv.Itoa(id)).Username != "paul" {
		t.Fatal("the new account was deleted")
	}
}

func TestDeleteAccountReturnsDBError(t *testing.T) {
	a := newAccounts(t)
	id, _, _ := a.createUser(t, "marie")
	asked := 0
	a.appManagement(t, 200, func(r *http.Request) { asked++ })
	dir := ownFolder(t, id)
	if err := a.db.Exec("CREATE TRIGGER keep_rows BEFORE DELETE ON o_users BEGIN SELECT RAISE(ABORT, 'kept'); END").Error; err != nil {
		t.Fatal(err)
	}

	if status, _ := a.c.do("DELETE", "/v1/users/"+strconv.Itoa(id), a.access, nil); status < 500 {
		t.Fatalf("a delete the database refused: %d, want an error", status)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("the folder: %v", err)
	}
	if a.users.GetUserAllInfoById(strconv.Itoa(id)).Id == 0 {
		t.Fatal("the account is gone")
	}
	if asked != 0 {
		t.Fatalf("AppManagement was asked %d times for an account that is still there", asked)
	}
}

func TestCustomConfStaysInOwnFolder(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	own := ownFolder(t, id)
	outside := filepath.Join(config.AppInfo.UserDataPath, "outside.json")
	writeFile(t, outside, `{"a":1}`)

	for _, key := range []string{"..%2Foutside", "..%2F..%2Foutside", "%2e%2e%2foutside"} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			status, res := a.c.do(method, "/v1/users/current/custom/"+key, access, map[string]string{"x": "y"})
			if status == http.StatusOK && res.Data != nil && res.Data["a"] != nil {
				t.Fatalf("%s with key %s read the file outside", method, key)
			}
		}
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != `{"a":1}` {
		t.Fatalf("the file outside the folder: %q %v", b, err)
	}
	a.c.expect(200, 200, "POST", "/v1/users/current/custom/mine", access, map[string]string{"x": "y"})
	if _, err := os.Stat(filepath.Join(own, "mine.json")); err != nil {
		t.Fatal(err)
	}
	a.c.expect(200, 200, "DELETE", "/v1/users/current/custom/mine", access, nil)
}

func TestImageServedOnlyFromAnAccountFolder(t *testing.T) {
	a := newAccounts(t)
	own := ownFolder(t, 1)
	writeFile(t, filepath.Join(own, "wall.png"), string(pngBytes(t)))
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "secret.png")
	writeFile(t, secret, string(pngBytes(t)))
	sibling := filepath.Join(config.AppInfo.UserDataPath, "1x", "sibling.png")
	writeFile(t, sibling, string(pngBytes(t)))

	img := func(p string) int {
		status, _ := a.get("/v1/users/image?path="+url.QueryEscape(p), "")
		return status
	}
	if got := img(own + "/wall.png"); got != 200 {
		t.Fatalf("a picture of an account folder: %d", got)
	}
	if got := img(own + "/../../" + filepath.Base(secretDir) + "/secret.png"); got == 200 {
		t.Fatal("a path leaving the folder was served")
	}
	if got := img(sibling); got == 200 {
		t.Fatal("a sibling folder was served")
	}
	if err := os.Symlink(secret, filepath.Join(own, "link.png")); err != nil {
		t.Logf("no symlink here: %v", err)
		return
	}
	if got := img(own + "/link.png"); got == 200 {
		t.Fatal("a link leading out of the folder was served")
	}
}

func TestPutAvatarKeepsTheRowWhenTheFileCannotBeWritten(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	// a folder where the file goes: the file cannot be created
	if err := os.MkdirAll(filepath.Join(ownFolder(t, id), "avatar.png", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := map[string]string{"file": base64.StdEncoding.EncodeToString(pngBytes(t))}
	if status, _ := a.c.do("PUT", "/v1/users/avatar", access, body); status != http.StatusInternalServerError {
		t.Fatalf("an avatar that cannot be written: %d, want 500", status)
	}
	if got := a.users.GetUserInfoById(strconv.Itoa(id)).Avatar; got != "" {
		t.Fatalf("avatar %q", got)
	}
}

func (a accounts) upload(path, token, name string, content []byte) (int, string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, _ := w.CreateFormFile("file", name)
	part.Write(content)
	w.Close()
	req := httptest.NewRequest("POST", path, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	a.c.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestUploadedImageStaysInOwnFolder(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	own := ownFolder(t, id)

	for _, key := range []string{"..%2Fescaped", "..%2F..%2Fescaped", "%2e%2e%2fescaped", "%2Ftmp%2Fescaped"} {
		a.upload("/v1/users/current/image/"+key, access, "pic.png", pngBytes(t))
		a.upload("/v1/users/current/image/ok?type=wallpaper", access, "../../escaped.png", pngBytes(t))
	}
	root := filepath.Dir(config.AppInfo.UserDataPath)
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.Contains(info.Name(), "escaped") && filepath.Dir(p) != own {
			t.Errorf("a file was written outside the folder: %s", p)
		}
		return nil
	})

	if status, _ := a.upload("/v1/users/current/image/wall", access, "pic.png", pngBytes(t)); status != http.StatusOK {
		t.Fatalf("a normal name: %d", status)
	}
	if _, err := os.Stat(filepath.Join(own, "wall.png")); err != nil {
		t.Fatalf("the upload of a normal name: %v", err)
	}
}

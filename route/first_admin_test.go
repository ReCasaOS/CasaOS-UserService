package route_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	v1 "github.com/ReCasaOS/CasaOS-UserService/route/v1"
	"github.com/ReCasaOS/CasaOS-UserService/service"
)

func firstAdminLocal(t *testing.T) {
	t.Helper()
	previous, dataPath := config.AppInfo.FirstAdmin, config.AppInfo.UserDataPath
	config.AppInfo.FirstAdmin, config.AppInfo.UserDataPath = "local", t.TempDir()
	t.Cleanup(func() { config.AppInfo.FirstAdmin, config.AppInfo.UserDataPath = previous, dataPath })
}

// local: no register key over the network, the web registration refused
func TestFirstAdminLocalRefusesTheWeb(t *testing.T) {
	_, c := newRig(t)
	firstAdminLocal(t)

	status := c.expect(200, 200, "GET", "/v1/users/status", "", nil)
	if status["key"] != "" || status["initialized"] != false || status["first_admin"] != "local" {
		t.Fatalf("status = %v, want no key, not initialised, first_admin local", status)
	}
	service.UserRegisterHash["k"] = "k" // even a key handed out before the switch
	c.expect(403, 10008, "POST", "/v1/users/register", "", map[string]string{"username": "owner", "password": "a long enough one", "key": "k"})
}

func TestCreateFirstAdminOnce(t *testing.T) {
	users, c := newRig(t)
	firstAdminLocal(t)

	if err := v1.CreateFirstAdmin(users, "owner", "short"); !errors.Is(err, v1.ErrPasswordTooShort) {
		t.Fatalf("short password: %v", err)
	}
	if err := v1.CreateFirstAdmin(users, "owner", "a long enough one"); err != nil {
		t.Fatal(err)
	}
	if user := users.GetUserAllInfoByName("owner"); user.Role != "admin" || !strings.HasPrefix(user.Password, argonPrefix) {
		t.Fatalf("first administrator stored as %+v", user)
	}
	c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "owner", "password": "a long enough one"})
	if err := v1.CreateFirstAdmin(users, "second", "a long enough one"); !errors.Is(err, v1.ErrAlreadyInitialised) {
		t.Fatalf("second call: %v", err)
	}
}

func TestReadFirstAdminCredentials(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	username, password, err := v1.ReadFirstAdminCredentials(strings.NewReader("owner\r\nsecret words\n"))
	if err != nil || username != "owner" || password != "secret words" {
		t.Fatalf("stdin: %q %q %v", username, password, err)
	}

	dir := t.TempDir()
	for name, content := range map[string]string{"username": "owner\n", "password": "from systemd"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	username, password, err = v1.ReadFirstAdminCredentials(strings.NewReader("ignored\nignored\n"))
	if err != nil || username != "owner" || password != "from systemd" {
		t.Fatalf("credentials: %q %q %v", username, password, err)
	}
}

// an input that must not be read
type unread struct{ t *testing.T }

func (u unread) Read([]byte) (int, error) {
	u.t.Error("credentials read although an account exists")
	return 0, errors.New("not to be read")
}

// -bootstrap-admin on a box that has an account: refused, non-zero, before a credential is read
func TestBootstrapRefusesBeforeReadingWhenAnAccountExists(t *testing.T) {
	users, _ := newRig(t)
	firstAdminLocal(t)
	if err := v1.CreateFirstAdmin(users, "owner", "a long enough one"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := v1.BootstrapFirstAdmin(users, unread{t}); !errors.Is(err, v1.ErrAlreadyInitialised) {
		t.Fatalf("second bootstrap: %v, want ErrAlreadyInitialised", err)
	}
}

func TestBootstrapCreatesTheFirstAdministrator(t *testing.T) {
	users, _ := newRig(t)
	firstAdminLocal(t)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if name, err := v1.BootstrapFirstAdmin(users, strings.NewReader("owner\na long enough one\n")); err != nil || name != "owner" {
		t.Fatalf("%q %v", name, err)
	}
	if users.GetUserAllInfoByName("owner").Role != "admin" {
		t.Fatal("no administrator")
	}
}

// a typo in [app] FirstAdmin is taken as web, and said at start
func TestFirstAdminValueKnown(t *testing.T) {
	previous := config.AppInfo.FirstAdmin
	t.Cleanup(func() { config.AppInfo.FirstAdmin = previous })
	for value, want := range map[string]bool{"": true, "web": true, "Local": true, " local ": true, "locale": false, "lokal": false} {
		config.AppInfo.FirstAdmin = value
		if got := v1.FirstAdminValueKnown(); got != want {
			t.Errorf("FirstAdminValueKnown(%q) = %v, want %v", value, got, want)
		}
	}
}

// stdin that is not a terminal (a pipe, /dev/null) is read; only a terminal is refused
func TestBootstrapReadsWhatIsNotATerminal(t *testing.T) {
	users, _ := newRig(t)
	firstAdminLocal(t)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if _, err := v1.BootstrapFirstAdmin(users, null); !errors.Is(err, v1.ErrEmptyCredentials) {
		t.Fatalf("/dev/null: %v, want ErrEmptyCredentials (read, nothing in it)", err)
	}
}

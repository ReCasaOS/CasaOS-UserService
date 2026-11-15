package route_test

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
)

// roleReply reads the internal role reply whole: data stays a string, rights is a sibling.
func (a accounts) roleReply(t *testing.T, id int) (data string, rights []string, hasRights bool) {
	t.Helper()
	in, secret := a.internal()
	req := httptest.NewRequest("GET", "/v1/users/role/"+strconv.Itoa(id), nil)
	req.Header.Set("X-Real-IP", in.ip)
	req.Header.Set("Authorization", secret)
	rec := httptest.NewRecorder()
	in.h.ServeHTTP(rec, req)
	var res struct {
		Data   string    `json:"data"`
		Rights *[]string `json:"rights"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || rec.Code != 200 {
		t.Fatalf("role reply %d: %v %s", rec.Code, err, rec.Body.String())
	}
	if res.Rights != nil {
		rights, hasRights = *res.Rights, true
	}
	return res.Data, rights, hasRights
}

func (a accounts) grant(t *testing.T, id int, rights ...string) {
	t.Helper()
	a.c.expect(200, 200, "PUT", "/v1/users/"+strconv.Itoa(id)+"/rights", a.access, map[string][]string{"rights": rights})
}

func TestGrantedRightAppearsInTheInternalReply(t *testing.T) {
	a := newAccounts(t)
	id, _, _ := a.createUser(t, "marie")
	a.grant(t, id, "storage", "vm", "storage")

	data, rights, _ := a.roleReply(t, id)
	if data != "user" || len(rights) != 2 || rights[0] != "storage" || rights[1] != "vm" {
		t.Fatalf("reply: %q %v", data, rights)
	}
	for _, row := range a.list(t) {
		if row["username"] == "marie" {
			if got, _ := row["rights"].([]interface{}); len(got) != 2 {
				t.Fatalf("listing: %v", row)
			}
		} else if got, ok := row["rights"].([]interface{}); !ok || len(got) != 0 {
			t.Fatalf("listing of the owner: %v", row)
		}
	}
}

func TestNewAccountHasNoRightsAndCreationIgnoresThem(t *testing.T) {
	a := newAccounts(t)
	a.c.expect(200, 200, "POST", "/v1/users", a.access, map[string]interface{}{"username": "marie", "password": "a long enough one", "rights": []string{"storage"}})
	id := a.users.GetUserAllInfoByName("marie").Id
	if _, rights, has := a.roleReply(t, id); !has || len(rights) != 0 {
		t.Fatalf("rights of a new account: %v present=%v", rights, has)
	}
}

func TestAdminReplyKeepsDataAStringWithEmptyRights(t *testing.T) {
	a := newAccounts(t)
	data, rights, has := a.roleReply(t, a.owner.Id)
	if data != "admin" || !has || rights == nil || len(rights) != 0 {
		t.Fatalf("admin reply: %q %v present=%v", data, rights, has)
	}
}

func TestUserCannotGrantRights(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	a.c.expect(403, 10011, "PUT", "/v1/users/"+strconv.Itoa(id)+"/rights", access, map[string][]string{"rights": {"storage"}})
	if _, rights, _ := a.roleReply(t, id); len(rights) != 0 {
		t.Fatalf("rights after a refused grant: %v", rights)
	}
}

func TestUnknownRightNameIsRefusedAndNothingIsWritten(t *testing.T) {
	a := newAccounts(t)
	id, _, _ := a.createUser(t, "marie")
	a.grant(t, id, "vm")
	a.c.expect(400, 4000, "PUT", "/v1/users/"+strconv.Itoa(id)+"/rights", a.access, map[string][]string{"rights": {"storage", "root"}})
	if _, rights, _ := a.roleReply(t, id); len(rights) != 1 || rights[0] != "vm" {
		t.Fatalf("rights after a refused grant: %v", rights)
	}
}

func TestRightsOfTheAdminCannotBeSetAndUnknownIdIs404(t *testing.T) {
	a := newAccounts(t)
	a.c.expect(400, 4000, "PUT", "/v1/users/"+strconv.Itoa(a.owner.Id)+"/rights", a.access, map[string][]string{"rights": {"vm"}})
	a.c.expect(404, 10006, "PUT", "/v1/users/9999/rights", a.access, map[string][]string{"rights": {"vm"}})
	a.c.expect(404, 10006, "PUT", "/v1/users/abc/rights", a.access, map[string][]string{"rights": {"vm"}})
	if _, rights, _ := a.roleReply(t, a.owner.Id); len(rights) != 0 {
		t.Fatalf("admin rights: %v", rights)
	}
}

func TestProfileSaveNeverChangesRights(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	a.grant(t, id, "fleet")
	a.c.expect(200, 200, "PUT", "/v1/users/current", access, map[string]interface{}{"nickname": "Marie", "rights": []string{"system"}})
	if _, rights, _ := a.roleReply(t, id); len(rights) != 1 || rights[0] != "fleet" {
		t.Fatalf("rights after a profile save: %v", rights)
	}
	// the service-level save, from a row read before the grant
	row := a.users.GetUserAllInfoById(strconv.Itoa(id))
	row.Rights = ""
	row.Nickname = "M"
	a.users.UpdateUser(row)
	if _, rights, _ := a.roleReply(t, id); len(rights) != 1 || rights[0] != "fleet" {
		t.Fatalf("rights after UpdateUser: %v", rights)
	}
}

func TestDeletedAccountTakesItsRightsAndANewOneStartsEmpty(t *testing.T) {
	a := newAccounts(t)
	a.appManagement(t, 200, nil)
	id, _, _ := a.createUser(t, "marie")
	a.grant(t, id, "storage", "system")
	a.c.expect(200, 200, "DELETE", "/v1/users/"+strconv.Itoa(id), a.access, nil)

	again, _, _ := a.createUser(t, "marie")
	if again == id {
		t.Fatalf("a number was given twice (%d)", id)
	}
	if _, rights, has := a.roleReply(t, again); !has || len(rights) != 0 {
		t.Fatalf("rights of the new account: %v", rights)
	}
}

func TestGarbageStoredRightsReadAsNone(t *testing.T) {
	a := newAccounts(t)
	id, _, _ := a.createUser(t, "marie")
	if err := a.db.Model(&model2.UserDBModel{}).Where("id = ?", id).Update("rights", "{not json").Error; err != nil {
		t.Fatal(err)
	}
	if data, rights, has := a.roleReply(t, id); data != "user" || !has || len(rights) != 0 {
		t.Fatalf("reply with garbage: %q %v", data, rights)
	}
}

func TestRightsBodyWithoutTheKeyIsRefusedAndEmptyListClears(t *testing.T) {
	a := newAccounts(t)
	id, _, _ := a.createUser(t, "marie")
	a.grant(t, id, "vm")
	path := "/v1/users/" + strconv.Itoa(id) + "/rights"
	a.c.expect(400, 4000, "PUT", path, a.access, map[string]interface{}{})
	a.c.expect(400, 4000, "PUT", path, a.access, map[string]interface{}{"rights": nil})
	if _, rights, _ := a.roleReply(t, id); len(rights) != 1 || rights[0] != "vm" {
		t.Fatalf("rights after refused bodies: %v", rights)
	}
	a.c.expect(200, 200, "PUT", path, a.access, map[string][]string{"rights": {}})
	if _, rights, _ := a.roleReply(t, id); len(rights) != 0 {
		t.Fatalf("rights after an explicit empty list: %v", rights)
	}
}

func TestCurrentAccountShowsOnlyItsOwnRights(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	a.grant(t, id, "backups")
	_, other, _ := a.createUser(t, "paul")

	own := func(token string) []interface{} {
		got, ok := a.c.expect(200, 200, "GET", "/v1/users/current", token, nil)["rights"].([]interface{})
		if !ok {
			t.Fatal("rights missing from current")
		}
		return got
	}
	if got := own(access); len(got) != 1 || got[0] != "backups" {
		t.Fatalf("marie's own: %v", got)
	}
	if got := own(other); len(got) != 0 {
		t.Fatalf("paul's own: %v", got)
	}
	if got := own(a.access); len(got) != 0 {
		t.Fatalf("admin's own: %v", got)
	}
	// a role other than admin is a user's, here as in the role route
	if err := a.db.Model(&model2.UserDBModel{}).Where("id = ?", id).Update("role", "").Error; err != nil {
		t.Fatal(err)
	}
	if got := own(access); len(got) != 1 || got[0] != "backups" {
		t.Fatalf("marie's own with an empty role: %v", got)
	}
	// nobody else's rights through the lookup by name, for the admin or another account
	for _, tok := range []string{a.access, other} {
		status, res := a.c.do("GET", "/v1/users/marie", tok, nil)
		if _, leaked := res.Data["rights"]; leaked {
			t.Fatalf("rights in the lookup by name (%d): %v", status, res.Data)
		}
	}
}

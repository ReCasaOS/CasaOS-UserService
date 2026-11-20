package route_test

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
)

type folder struct {
	Path  string `json:"path"`
	Write bool   `json:"write"`
}

// foldersReply reads the folders of the internal role reply.
func (a accounts) foldersReply(t *testing.T, id int) []folder {
	t.Helper()
	in, secret := a.internal()
	req := httptest.NewRequest("GET", "/v1/users/role/"+strconv.Itoa(id), nil)
	req.Header.Set("X-Real-IP", in.ip)
	req.Header.Set("Authorization", secret)
	rec := httptest.NewRecorder()
	in.h.ServeHTTP(rec, req)
	var res struct {
		Folders *[]folder `json:"folders"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || rec.Code != 200 || res.Folders == nil {
		t.Fatalf("role reply %d: %v %s", rec.Code, err, rec.Body.String())
	}
	return *res.Folders
}

func (a accounts) giveFolders(t *testing.T, id, status, code int, folders []folder) {
	t.Helper()
	a.c.expect(status, code, "PUT", "/v1/users/"+strconv.Itoa(id)+"/folders", a.access, map[string][]folder{"folders": folders})
}

func TestGivenFoldersAppearInTheInternalReplyAndTheListing(t *testing.T) {
	a := newAccounts(t)
	id, _, _ := a.createUser(t, "marie")
	a.giveFolders(t, id, 200, 200, []folder{{"/DATA/Media", false}, {"/DATA/Kids", true}})

	got := a.foldersReply(t, id)
	if len(got) != 2 || got[0] != (folder{"/DATA/Media", false}) || got[1] != (folder{"/DATA/Kids", true}) {
		t.Fatalf("reply: %v", got)
	}
	for _, row := range a.list(t) {
		if row["username"] == "marie" {
			if f, _ := row["folders"].([]interface{}); len(f) != 2 {
				t.Fatalf("listing: %v", row)
			}
		}
	}
	// the owner reaches everything: no folders of its own
	if f := a.foldersReply(t, a.owner.Id); len(f) != 0 {
		t.Fatalf("owner folders: %v", f)
	}
}

// One folder, one mode: a list that leaves a doubt, or widens a path, is refused whole.
func TestABadListOfFoldersIsRefusedAndNothingIsWritten(t *testing.T) {
	a := newAccounts(t)
	id, _, _ := a.createUser(t, "marie")
	a.giveFolders(t, id, 200, 200, []folder{{"/DATA/Media", false}})

	for _, bad := range [][]folder{
		{{"/", true}},
		{{"DATA", false}},
		{{"/DATA/../etc", false}},
		{{"/DATA//x", false}},
		{{"/DATA/x/", false}},
		{{"/DATA/A", true}, {"/DATA/A/x", false}},
		{{"/DATA/A", true}, {"/DATA/A", false}},
	} {
		a.giveFolders(t, id, 400, 4000, bad)
	}
	if got := a.foldersReply(t, id); len(got) != 1 || got[0].Path != "/DATA/Media" {
		t.Fatalf("folders after refused lists: %v", got)
	}
}

func TestOnlyTheOwnerGivesFoldersAndNotToItself(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	a.c.expect(403, 10011, "PUT", "/v1/users/"+strconv.Itoa(id)+"/folders", access, map[string][]folder{"folders": {{"/DATA", true}}})
	a.giveFolders(t, a.owner.Id, 400, 4000, []folder{{"/DATA", true}})
	a.c.expect(404, 10006, "PUT", "/v1/users/9999/folders", a.access, map[string][]folder{"folders": {{"/DATA", true}}})
	if got := a.foldersReply(t, id); len(got) != 0 {
		t.Fatalf("folders: %v", got)
	}
}

// files is derived from the folders: it is not a right that can be set.
func TestFilesIsNotARightOfItsOwn(t *testing.T) {
	a := newAccounts(t)
	id, _, _ := a.createUser(t, "marie")
	a.c.expect(400, 4000, "PUT", "/v1/users/"+strconv.Itoa(id)+"/rights", a.access, map[string][]string{"rights": {"files"}})
}

func TestProfileSaveNeverChangesFoldersAndEmptyListClears(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	a.giveFolders(t, id, 200, 200, []folder{{"/DATA/Kids", true}})
	a.c.expect(200, 200, "PUT", "/v1/users/current", access, map[string]interface{}{"nickname": "Marie", "folders": []folder{{"/", true}}})
	row := a.users.GetUserAllInfoById(strconv.Itoa(id))
	row.Folders, row.Nickname = "", "M"
	a.users.UpdateUser(row)
	if got := a.foldersReply(t, id); len(got) != 1 || got[0].Path != "/DATA/Kids" {
		t.Fatalf("folders after a profile save: %v", got)
	}
	a.c.expect(400, 4000, "PUT", "/v1/users/"+strconv.Itoa(id)+"/folders", a.access, map[string]interface{}{})
	a.giveFolders(t, id, 200, 200, []folder{})
	if got := a.foldersReply(t, id); len(got) != 0 {
		t.Fatalf("folders after clearing: %v", got)
	}
}

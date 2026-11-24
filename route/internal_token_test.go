package route_test

import (
	"crypto/ecdsa"
	"net/http"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	v1 "github.com/ReCasaOS/CasaOS-UserService/route/v1"
	"github.com/ReCasaOS/CasaOS-UserService/service"
)

const internalTokenPath = "/v1/users/internal/access-token"

// A signed-in owner holds a JWT the group's middleware lets through: the route is still not theirs.
func TestInternalAccessTokenRefusesAJWT(t *testing.T) {
	a := newAccounts(t)
	a.c.expect(403, 10011, "POST", internalTokenPath, a.access, map[string]int{"id": a.owner.Id})
}

func TestInternalAccessTokenRefusesNoAuth(t *testing.T) {
	a := newAccounts(t)
	status, _ := a.c.do("POST", internalTokenPath, "", map[string]int{"id": a.owner.Id})
	if status != http.StatusUnauthorized {
		t.Fatalf("no credentials: %d, want 401", status)
	}
}

func TestInternalAccessTokenUnknownAccount(t *testing.T) {
	a := newAccounts(t)
	in, auth := a.internal()
	in.expect(404, 10006, "POST", internalTokenPath, auth, map[string]int{"id": 999})
	in.expect(400, 400, "POST", internalTokenPath, auth, map[string]int{"id": 0})
}

func TestInternalAccessTokenIsAnOrdinaryAccessToken(t *testing.T) {
	a := newAccounts(t)
	in, auth := a.internal()
	data := in.expect(200, 200, "POST", internalTokenPath, auth, map[string]int{"id": a.owner.Id})

	token, _ := data["access_token"].(string)
	expiresAt, _ := data["expires_at"].(float64)
	valid, claims, err := jwt.Validate(token, func() (*ecdsa.PublicKey, error) {
		_, pub := service.MyService.User().GetKeyPair()
		return pub, nil
	})
	if err != nil || !valid {
		t.Fatalf("token does not validate: %v", err)
	}
	if claims.Issuer != jwt.AccessIssuer || claims.ID != a.owner.Id || !v1.TokenIsOfTheAccount(claims) {
		t.Fatalf("claims: %+v", claims)
	}
	if left := time.Until(claims.ExpiresAt.Time); left < 4*time.Minute || left > 5*time.Minute {
		t.Fatalf("expires in %v, want 4 to 5 minutes", left)
	}
	if d := int64(expiresAt) - claims.ExpiresAt.Unix(); d < -1 || d > 1 { // two clock reads
		t.Fatalf("expires_at %v, token says %d", expiresAt, claims.ExpiresAt.Unix())
	}
	// and the route that takes a user's token takes it
	a.c.expect(200, 200, "GET", "/v1/users/current", token, nil)
}

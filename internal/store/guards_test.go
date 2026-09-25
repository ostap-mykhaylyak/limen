package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/model"
)

func TestALocationNeedsAnExistingAccessList(t *testing.T) {
	s, _ := open(t)
	h := host("app", "app.example.com")
	h.Locations = []model.Location{{Path: "/admin/", AccessList: "staff"}}
	if _, err := s.Put(h, cli); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "staff") {
		t.Fatalf("a location guarded by a missing list: err = %v, want ErrConflict", err)
	}
	mustPut(t, s, acl("staff"))
	mustPut(t, s, h)

	err := s.Delete(model.KindAccessList, "staff", cli)
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "proxy host app") {
		t.Errorf("deleting the list a location uses: err = %v", err)
	}
}

func TestAStreamIsGuardedByAddressesOnly(t *testing.T) {
	s, _ := open(t)
	withUsers := acl("gate")
	withUsers.Users = []model.BasicUser{{Username: "ops", Password: "$apr1$abcdefgh$0123456789012345678901"}}
	mustPut(t, s, withUsers)
	mustPut(t, s, acl("office"))

	pg := stream("pg", 5432, "tcp")
	pg.AccessList = "missing"
	if _, err := s.Put(pg, cli); !errors.Is(err, ErrConflict) {
		t.Errorf("a stream on a missing list: err = %v", err)
	}
	pg.AccessList = "gate"
	if _, err := s.Put(pg, cli); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "password") {
		t.Errorf("a stream on a list with users: err = %v", err)
	}
	pg.AccessList = "office"
	mustPut(t, s, pg)

	// The list cannot gain a user behind the stream's back.
	office, _ := s.Get(model.KindAccessList, "office")
	a := office.(*model.AccessList)
	a.Users = withUsers.Users
	if _, err := s.Put(a, cli); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "stream") {
		t.Errorf("adding a user to a stream's list: err = %v", err)
	}
	if err := s.Delete(model.KindAccessList, "office", cli); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "stream pg") {
		t.Errorf("deleting a stream's list: err = %v", err)
	}
	if got := s.AccessUsers("office"); len(got) != 1 || got[0] != "stream pg" {
		t.Errorf("AccessUsers = %v", got)
	}
}

func TestLoadFailsClosedOnLocationsAndStreams(t *testing.T) {
	dirs := Under(t.TempDir())
	write(t, dirs.ProxyHosts, "app.yaml", "kind: proxy_host\nname: app\ndomains: [app.example.com]\nforward: {host: 10.0.0.1, port: 80}\n"+
		"locations:\n  - path: /admin/\n    access_list: staff\n")
	write(t, dirs.Streams, "pg.yaml", "kind: stream\nname: pg\nlisten_port: 5432\nforward: {host: 10.0.0.9, port: 5432}\naccess_list: gate\n")
	write(t, dirs.Streams, "redis.yaml", "kind: stream\nname: redis\nlisten_port: 6379\nforward: {host: 10.0.0.9, port: 6379}\naccess_list: withusers\n")
	write(t, dirs.AccessLists, "withusers.yaml", "kind: access_list\nname: withusers\nusers:\n  - username: ops\n    password: $apr1$abcdefgh$0123456789012345678901\n")

	s, err := Open(dirs)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []struct {
		kind model.Kind
		name string
	}{{model.KindProxyHost, "app"}, {model.KindStream, "pg"}, {model.KindStream, "redis"}} {
		if _, err := s.Get(ref.kind, ref.name); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s %s was loaded without its guard", ref.kind, ref.name)
		}
	}
	w := strings.Join(s.Warnings(), "\n")
	for _, want := range []string{"staff", "gate", "password"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings do not mention %q: %s", want, w)
		}
	}
}

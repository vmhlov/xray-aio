package orchestrator

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/vmhlov/xray-aio/internal/state"
)

func TestSaveAndLoadProfileStateRoundtrip(t *testing.T) {
	t.Parallel()

	original := &ProfileState{
		Profile: "home-stealth",
		Domain:  "example.com",
		Email:   "ops@example.com",
		Xray: &XrayState{
			Mode:       "vision",
			UUID:       "11111111-2222-4333-8444-555555555555",
			PrivateKey: "priv-base64",
			PublicKey:  "pub-base64",
			ShortIDs:   []string{"abcdef0123456789"},
			ListenPort: 443,
			Dest:       "127.0.0.1:8443",
		},
		Naive: &NaiveState{
			Username:   "alice",
			Password:   "0123456789abcdef",
			ListenPort: 8444,
		},
		Subscription: &SubscriptionState{
			Secret:          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			DefaultClientID: "default",
			Token:           "id.tag",
		},
	}
	s := &state.State{}
	if err := saveProfileState(s, original); err != nil {
		t.Fatalf("saveProfileState: %v", err)
	}
	if s.Profile != "home-stealth" {
		t.Errorf("saveProfileState should mirror Profile to State.Profile, got %q", s.Profile)
	}
	if s.Domain != "example.com" {
		t.Errorf("saveProfileState should mirror Domain to State.Domain, got %q", s.Domain)
	}
	loaded, err := loadProfileState(s)
	if err != nil {
		t.Fatalf("loadProfileState: %v", err)
	}
	if !reflect.DeepEqual(original, loaded) {
		t.Fatalf("roundtrip mismatch:\n  want %+v\n  got  %+v", original, loaded)
	}
}

func TestLoadProfileStateMissing(t *testing.T) {
	t.Parallel()

	cases := map[string]*state.State{
		"nil state":                            nil,
		"nil transports":                       {},
		"transports without orchestrator slot": {Transports: map[string]json.RawMessage{"xray": json.RawMessage(`{}`)}},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			ps, err := loadProfileState(s)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ps != nil {
				t.Fatalf("expected nil profile state, got %+v", ps)
			}
		})
	}
}

func TestLoadProfileStateRejectsCorruptJSON(t *testing.T) {
	t.Parallel()

	s := &state.State{Transports: map[string]json.RawMessage{stateKey: json.RawMessage(`{"profile": 12`)}}
	_, err := loadProfileState(s)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestSaveProfileStateRejectsNil(t *testing.T) {
	t.Parallel()

	if err := saveProfileState(nil, &ProfileState{}); err == nil {
		t.Error("expected error for nil state")
	}
	if err := saveProfileState(&state.State{}, nil); err == nil {
		t.Error("expected error for nil profile")
	}
}

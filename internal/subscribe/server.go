package subscribe

import (
	"errors"
	"net/http"
	"strings"
)

// PathPrefix is the URL prefix every subscription URL lives under.
// Hard-coded so callers can't accidentally pick a path that collides
// with the selfsteal page.
const PathPrefix = "/sub/"

// BundleResolver returns the Bundle associated with id. Returning
// (Bundle{}, [ErrNotFound]) makes Handler answer 404 — any other
// error becomes 500.
//
// Implementations are typically state.json-backed lookups.
type BundleResolver interface {
	Resolve(id string) (Bundle, error)
}

// ErrNotFound is the sentinel a [BundleResolver] returns to indicate
// "the id was authentic but no client matches it". Returning this
// rather than nil lets Handler distinguish "bad token" (401) from
// "valid token, removed client" (404).
var ErrNotFound = errors.New("subscribe: not found")

// Handler returns an http.Handler that serves /sub/<token>:
//
//   - GET /sub/<token>            → HTML landing page
//   - GET /sub/<token>?plain=1    → newline-separated URIs (for clients)
//   - everything else             → 404
//
// The handler verifies the HMAC tag before calling the resolver, so a
// hostile caller can't enumerate clients by hammering ids.
//
// The secret-length check matches [VerifyToken]'s lower bound so an
// undersized secret can never be silently swallowed (every request
// would 404 because VerifyToken returns "secret too short", giving
// the operator no useful signal).
func Handler(secret []byte, r BundleResolver) http.Handler {
	if len(secret) < SecretBytes/2 || r == nil {
		// Programmer error — fail loudly at construction time
		// rather than serving an open endpoint.
		panic("subscribe.Handler: secret (>= SecretBytes/2 bytes) and resolver are required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc(PathPrefix, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := strings.TrimPrefix(req.URL.Path, PathPrefix)
		if token == "" || strings.Contains(token, "/") {
			http.NotFound(w, req)
			return
		}
		id, err := VerifyToken(secret, token)
		if err != nil {
			// Match a real 404 to avoid signalling that the
			// path is the right place to brute-force tokens.
			http.NotFound(w, req)
			return
		}
		bundle, err := r.Resolve(id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				http.NotFound(w, req)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if req.URL.Query().Get("plain") == "1" {
			body, err := RenderPlainText(bundle)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte(body))
			return
		}
		body, err := RenderHTML(bundle)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	})
	return mux
}

// MapResolver is an in-memory [BundleResolver] used by tests and by
// the orchestrator until it wires a real state.json-backed lookup.
type MapResolver map[string]Bundle

// Resolve implements [BundleResolver].
func (m MapResolver) Resolve(id string) (Bundle, error) {
	b, ok := m[id]
	if !ok {
		return Bundle{}, ErrNotFound
	}
	return b, nil
}

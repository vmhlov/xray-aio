package naive

import _ "embed"

//go:embed selfsteal/index.html
var selfStealIndex []byte

// SelfStealIndex returns the bytes of the embedded fallback HTML page
// that is served when forward_proxy auth is missing — i.e. to active
// probers and to anyone who navigates to https://Domain/ in a browser.
func SelfStealIndex() []byte {
	out := make([]byte, len(selfStealIndex))
	copy(out, selfStealIndex)
	return out
}

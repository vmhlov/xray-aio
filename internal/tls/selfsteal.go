package tls

import _ "embed"

// SelfStealIndex is a deliberately bland, mostly-empty landing page.
// The content is unimportant — what matters is that an HTTPS GET on /
// returns 200 with normal HTML so passive observers see "just a
// website". Operators are expected to replace it with their own
// indistinguishable-from-typical content.
//
//go:embed selfsteal/index.html
var SelfStealIndex []byte

// Package sysuser ensures system users and matching groups exist on
// the host. xray-aio's transport managers (xray, naive) need a
// dedicated unprivileged account to drop privileges to via systemd's
// User=/Group= directives — without it systemd refuses to start the
// unit with status=217/USER.
//
// Ensure is idempotent: a getent pre-check skips the create call when
// the account already exists, so it is safe to invoke on every
// install.
package sysuser

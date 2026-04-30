package sysuser

import (
	"context"
	"errors"
	"fmt"
)

// Runner executes external commands. It mirrors the shape every
// transport manager already uses, so callers pass their existing
// runner and tests share the same fake.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Ensure makes sure a system user and a matching primary group both
// exist. If either is missing, the missing one is created via
// shadow-utils. Idempotent — repeated calls do nothing once both
// entries are present.
//
// The created user has a system UID, no home directory on disk
// (--home-dir /nonexistent), and /usr/sbin/nologin as shell, which
// matches the convention of upstream Caddy/Xray packages and prevents
// the account from ever being used for an interactive login.
//
// xray-aio targets glibc-based distros (Debian, Ubuntu, RHEL family)
// where getent/groupadd/useradd ship as part of the shadow-utils
// package. Busybox-only systems (Alpine without shadow-utils) are not
// supported.
func Ensure(ctx context.Context, runner Runner, name string) error {
	if name == "" {
		return errors.New("sysuser: empty name")
	}
	if exists(ctx, runner, "passwd", name) {
		return nil
	}
	if !exists(ctx, runner, "group", name) {
		if _, err := runner.Run(ctx, "groupadd", "--system", name); err != nil {
			return fmt.Errorf("groupadd %s: %w", name, err)
		}
	}
	if _, err := runner.Run(ctx, "useradd",
		"--system",
		"--no-create-home",
		"--home-dir", "/nonexistent",
		"--shell", "/usr/sbin/nologin",
		"--gid", name,
		name,
	); err != nil {
		return fmt.Errorf("useradd %s: %w", name, err)
	}
	return nil
}

// exists reports whether the given NSS database entry resolves. We
// treat any non-nil error as "absent" — getent's standard exit code
// for "not found" is 2, but on misconfigured NSS we still want to
// fall through to a create attempt rather than wedge install on a
// transient lookup error.
func exists(ctx context.Context, runner Runner, db, name string) bool {
	_, err := runner.Run(ctx, "getent", db, name)
	return err == nil
}

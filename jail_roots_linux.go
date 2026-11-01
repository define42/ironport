//go:build linux

package ironport

import (
	"fmt"
	"log"
	"time"

	"github.com/define42/ironport/internal/jailfs"
)

// ValidateJailRoots checks kernel support and logs warnings for configured roots
// that cannot currently be opened securely. Only a capability-probe failure is
// returned as an error. Unusable roots are advisory: applications may provision
// directories after registering users, but authentication fails until the root
// can be opened. It does not check file permissions for later I/O operations.
//
// ListenAndServe and HttpIngest call this automatically before serving requests.
// It is safe to call concurrently with user changes and active connections.
// Checks and logging run outside the user lock and may block on filesystem or
// logger I/O. Diagnostic handles are closed immediately; authentication still
// opens and retains its own root, so validation does not guarantee a later login.
func (s *Server) ValidateJailRoots() error {
	if err := jailfs.CheckSupport(); err != nil {
		return fmt.Errorf("ironport: %w", err)
	}
	type configuredRoot struct {
		username string
		root     string
		revision uint64
	}
	s.mu.RLock()
	roots := make([]configuredRoot, 0, len(s.users))
	for username, user := range s.users {
		roots = append(roots, configuredRoot{username, user.Root, s.userRevisions[username]})
	}
	s.mu.RUnlock()
	for _, root := range roots {
		s.warnUnusableJailRoot(root.username, root.root, root.revision)
	}
	return nil
}

func checkJailRoot(root string) error {
	jfs, err := jailfs.Open(root)
	if err != nil {
		return err
	}
	return jfs.Close()
}

func (s *Server) warnUnusableJailRoot(username, root string, revision uint64) {
	if err := checkJailRoot(root); err != nil {
		s.logUnusableJailRootIfCurrent(username, root, revision, err)
	}
}

func (s *Server) logUnusableJailRootIfCurrent(username, root string, revision uint64, err error) {
	if !s.userRevisionMatches(username, revision) {
		return
	}
	// No server lock is held while calling the application's logger. A later
	// user update may race the log write; the revision identifies the check.
	// Quote user, path, and error text to escape control characters.
	log.Printf("warning: jail-root check failed for user %q revision %d at %q: %q", username, revision, root, err.Error())
}

func (s *Server) logRootAuthFailure(username, root string, revision uint64, err error) {
	if !s.userRevisionMatches(username, revision) {
		return
	}
	if sample, suppressed := s.rootAuthLogs.allow(time.Now()); sample {
		// Keep details server-side and bound messages independently of ordinary
		// login failures. The revision identifies the failed snapshot check.
		// Quote user, path, and error text to escape control characters.
		log.Printf("authentication jail-root check failed user=%q revision=%d root=%q error=%q suppressed=%d",
			username, revision, root, err.Error(), suppressed)
	}
}

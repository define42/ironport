package authlimit

import (
	"fmt"
	"testing"
	"time"
)

func collidingUsername(t *testing.T, l *Limiter, username string) string {
	t.Helper()
	slot := l.locate(username, "192.0.2.1").user
	for i := range 4096 {
		candidate := fmt.Sprintf("collision-%d", i)
		if candidate != username && l.locate(candidate, "192.0.2.1").user == slot {
			return candidate
		}
	}
	t.Fatal("could not find a colliding username")
	return ""
}

func TestAuthLimiterSuccessClearsExclusiveUsernameBackoff(t *testing.T) {
	t.Parallel()
	l := New(Config{MaxEntries: 16})
	now := time.Now()
	const failingIP = "192.0.2.1"
	goodIP := differentSource(t, l, failingIP)
	good := admit(t, l, "alice", goodIP, now)
	for range 3 {
		l.Result(admit(t, l, "alice", failingIP, now), false, now)
	}
	l.Result(good, true, now)
	admit(t, l, "alice", goodIP, now)
	if _, retry := l.Allow("alice", failingIP, now); retry != 250*time.Millisecond {
		t.Fatalf("successful account also cleared source backoff: %v", retry)
	}
	if user := l.users[good.user]; user.owned || user.mixed || user.owner != [32]byte{} {
		t.Fatal("successful authentication retained resolved failure ownership")
	}
}

func TestAuthLimiterCollidingSuccessPreservesOtherFailureOwner(t *testing.T) {
	t.Parallel()
	l := New(Config{MaxEntries: 16})
	now := time.Now()
	const failingIP = "192.0.2.1"
	goodIP := differentSource(t, l, failingIP)
	other := collidingUsername(t, l, "alice")
	good := admit(t, l, other, goodIP, now)
	for range 3 {
		l.Result(admit(t, l, "alice", failingIP, now), false, now)
	}
	l.Result(good, true, now)
	if _, retry := l.Allow(other, goodIP, now); retry != 250*time.Millisecond {
		t.Fatalf("colliding account cleared another user's backoff: %v", retry)
	}
	if user := l.users[good.user]; user.mixed || user.owner == good.username {
		t.Fatal("colliding success changed the existing failure owner")
	}
}

func TestAuthLimiterUnfailedCollisionsDoNotPreventRecovery(t *testing.T) {
	t.Parallel()
	for _, order := range []string{"before failures", "after failures"} {
		for _, success := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/success=%t", order, success), func(t *testing.T) {
				t.Parallel()
				testUnfailedCollisionRecovery(t, order, success)
			})
		}
	}
}

func testUnfailedCollisionRecovery(t *testing.T, order string, success bool) {
	t.Helper()
	l := New(Config{MaxEntries: 16})
	now := time.Now()
	goodIP := differentSource(t, l, "192.0.2.1")
	good := admit(t, l, "alice", goodIP, now)
	offer := func() {
		attempt := admit(t, l, collidingUsername(t, l, "alice"), goodIP, now)
		if success {
			l.Result(attempt, true, now)
		}
		// Without Result this models an unsigned SSH key eligibility query.
	}
	if order == "before failures" {
		offer()
	}
	for range 2 {
		l.Result(admit(t, l, "alice", "192.0.2.1", now), false, now)
	}
	if order == "after failures" {
		offer()
	}
	l.Result(admit(t, l, "alice", "192.0.2.1", now), false, now)
	l.Result(good, true, now)
	admit(t, l, "alice", goodIP, now)
	if user := l.users[good.user]; user.owned || user.mixed || user.failures != 0 {
		t.Fatal("unfailed collision prevented the genuine failure owner's recovery")
	}
}

func TestAuthLimiterResolvedOwnerDoesNotMixWithLaterFailures(t *testing.T) {
	t.Parallel()
	l := New(Config{MaxEntries: 16})
	now := time.Now()
	const goodIP = "192.0.2.1"
	failed := admit(t, l, "alice", goodIP, now)
	good := admit(t, l, "alice", goodIP, now)
	l.Result(failed, false, now)
	l.Result(good, true, now)
	other := collidingUsername(t, l, "alice")
	otherGood := admit(t, l, other, goodIP, now)
	badIP := differentSource(t, l, goodIP)
	for range 3 {
		l.Result(admit(t, l, other, badIP, now), false, now)
	}
	if user := l.users[good.user]; user.mixed || user.owner != otherGood.username {
		t.Fatal("previously resolved failure history poisoned a later owner")
	}
	l.Result(otherGood, true, now)
	admit(t, l, other, goodIP, now)
}

func TestAuthLimiterMixedFailuresPreserveBackoff(t *testing.T) {
	t.Parallel()
	l := New(Config{MaxEntries: 16})
	now := time.Now()
	goodIP := differentSource(t, l, "192.0.2.1")
	other := collidingUsername(t, l, "alice")
	good := []Attempt{admit(t, l, "alice", goodIP, now), admit(t, l, other, goodIP, now)}
	for _, username := range []string{"alice", other, other} {
		l.Result(admit(t, l, username, "192.0.2.1", now), false, now)
	}
	for _, attempt := range good {
		l.Result(attempt, true, now)
		if retry := l.RetryBackoff(attempt, now); retry != 250*time.Millisecond {
			t.Fatalf("one colliding user cleared mixed failure history: %v", retry)
		}
	}
	if !l.users[good[0].user].mixed {
		t.Fatal("failures from distinct usernames did not mark the slot mixed")
	}
}

func TestAuthLimiterDelayedFailureCannotLoseItsOwner(t *testing.T) {
	t.Parallel()
	l := New(Config{MaxEntries: 16, EntryTTL: time.Minute})
	now := time.Now()
	var pending [3]Attempt
	for i := range pending {
		pending[i] = admit(t, l, "alice", "192.0.2.1", now)
	}
	other := collidingUsername(t, l, "alice")
	otherIP := differentSource(t, l, "192.0.2.1")
	later := now.Add(2 * time.Minute)
	good := admit(t, l, other, otherIP, later)
	l.Result(admit(t, l, other, otherIP, later), false, later)
	for _, attempt := range pending {
		l.Result(attempt, false, later)
	}
	l.Result(good, true, later)
	if _, retry := l.Allow(other, otherIP, later); retry != 500*time.Millisecond {
		t.Fatalf("new owner erased delayed failures from the old owner: %v", retry)
	}
	if !l.users[good.user].mixed {
		t.Fatal("delayed failure did not mark the reused slot mixed")
	}
}

func TestAuthLimiterDelayedSuccessCannotClearNewOwner(t *testing.T) {
	t.Parallel()
	l := New(Config{MaxEntries: 16, EntryTTL: time.Minute})
	now := time.Now()
	old := admit(t, l, "alice", "192.0.2.1", now)
	other := collidingUsername(t, l, "alice")
	otherIP := differentSource(t, l, "192.0.2.1")
	later := now.Add(2 * time.Minute)
	for range 3 {
		l.Result(admit(t, l, other, otherIP, later), false, later)
	}
	l.Result(old, true, later)
	if user := l.users[old.user]; user.failures != 3 || !user.blockedUntil.After(later) || user.mixed {
		t.Fatal("old successful result changed a new owner's failure history")
	}
}

func TestAuthLimiterMixedSlotRecoversAfterIdleExpiry(t *testing.T) {
	t.Parallel()
	l := New(Config{MaxEntries: 16, EntryTTL: time.Minute})
	now := time.Now()
	const ip = "192.0.2.1"
	alice := admit(t, l, "alice", ip, now)
	other := collidingUsername(t, l, "alice")
	l.Result(alice, false, now)
	l.Result(admit(t, l, other, ip, now), false, now)
	if !l.users[alice.user].mixed {
		t.Fatal("colliding failures did not mark slot mixed")
	}
	later := now.Add(time.Minute)
	admit(t, l, "alice", ip, later)
	if user := l.users[alice.user]; user.mixed || user.owned || user.failures != 0 {
		t.Fatal("idle, fully refilled slot did not clear its failure history")
	}
}

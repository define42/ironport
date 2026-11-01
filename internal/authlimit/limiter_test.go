package authlimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func admit(t *testing.T, l *Limiter, username, ip string, now time.Time) Attempt {
	t.Helper()
	attempt, retry := l.Allow(username, ip, now)
	if retry != 0 {
		t.Fatalf("admission for %q from %q rejected: %v", username, ip, retry)
	}
	return attempt
}

func differentSource(t *testing.T, l *Limiter, ip string) string {
	t.Helper()
	slot := l.locate("", ip).ip
	for i := range 1024 {
		candidate := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		if l.locate("", candidate).ip != slot {
			return candidate
		}
	}
	t.Fatal("could not find a distinct source slot")
	return ""
}

func differentUsername(t *testing.T, l *Limiter, username string) string {
	t.Helper()
	slot := l.locate(username, "192.0.2.1").user
	for i := range 1024 {
		candidate := fmt.Sprintf("different-%d", i)
		if l.locate(candidate, "192.0.2.1").user != slot {
			return candidate
		}
	}
	t.Fatal("could not find a distinct username slot")
	return ""
}

func TestAuthLimiterIdentityBuckets(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		users [3]string
		ips   [3]string
	}{
		{name: "IP across usernames", users: [3]string{"a", "b", "c"}, ips: [3]string{"192.0.2.1", "192.0.2.1", "192.0.2.1"}},
		{name: "username across IPs", users: [3]string{"a", "a", "a"}, ips: [3]string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}},
		{name: "IPv4 mapped address", users: [3]string{"a", "b", "c"}, ips: [3]string{"192.0.2.1", "::ffff:192.0.2.1", "192.0.2.1"}},
		{name: "IPv6 prefix", users: [3]string{"a", "b", "c"}, ips: [3]string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:ffff::1"}},
		{name: "IPv6 zones", users: [3]string{"a", "b", "c"}, ips: [3]string{"fe80::1%eth0", "fe80::2%eth1", "fe80::3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := New(Config{IPBurst: 2, UserBurst: 2, IPInterval: time.Hour, UserInterval: time.Hour})
			now := time.Now()
			for i := range 3 {
				_, retry := l.Allow(tc.users[i], tc.ips[i], now)
				if (retry > 0) != (i == 2) {
					t.Fatalf("attempt %d retry=%v", i+1, retry)
				}
			}
			admit(t, l, tc.users[2], tc.ips[2], now.Add(time.Hour))
		})
	}
}

func TestAuthLimiterGlobalBound(t *testing.T) {
	t.Parallel()
	l := New(Config{GlobalBurst: 2, GlobalInterval: time.Hour})
	now := time.Now()
	for i := range 3 {
		_, retry := l.Allow(fmt.Sprintf("user%d", i), fmt.Sprintf("192.0.2.%d", i+1), now)
		if (retry > 0) != (i == 2) {
			t.Fatalf("attempt %d retry=%v", i+1, retry)
		}
	}
}

func TestAuthLimiterLocalRejectionDoesNotConsumeGlobal(t *testing.T) {
	t.Parallel()
	l := New(Config{GlobalBurst: 2, GlobalInterval: time.Hour, IPBurst: 1, IPInterval: time.Hour})
	now := time.Now()
	const attackerIP = "192.0.2.1"
	admit(t, l, "attacker-first", attackerIP, now)
	before := make(map[int]userBucket, len(l.users))
	for slot, value := range l.users {
		before[slot] = *value
	}
	for i := range 100 {
		if _, retry := l.Allow(fmt.Sprintf("attacker-%d", i), attackerIP, now); retry == 0 {
			t.Fatal("exhausted IP bucket permitted another attempt")
		}
	}
	if len(l.users) != len(before) {
		t.Fatal("locally rejected attempts allocated username slots")
	}
	for i := range before {
		if before[i] != *l.users[i] {
			t.Fatal("locally rejected attempt changed username state")
		}
	}
	admit(t, l, "victim", differentSource(t, l, attackerIP), now)
}

func TestAuthLimiterSuccessPreservesSharedIPBackoff(t *testing.T) {
	t.Parallel()
	const backoff = time.Minute
	l := New(Config{BackoffInitial: backoff, BackoffMax: backoff})
	now := time.Now()
	const clientIP = "192.0.2.1"
	trusted := admit(t, l, "trusted", clientIP, now)
	for i := range 3 {
		attempt := admit(t, l, fmt.Sprintf("target-%d", i), clientIP, now)
		l.Result(attempt, false, now)
	}
	l.Result(trusted, true, now)
	if _, retry := l.Allow("another-target", clientIP, now); retry != backoff {
		t.Fatalf("successful username cleared shared-IP backoff: got %v, want %v", retry, backoff)
	}
}

func TestAuthLimiterBackoff(t *testing.T) {
	t.Parallel()
	l := New(Config{})
	now := time.Now()
	for range 3 {
		l.Result(admit(t, l, "alice", "192.0.2.1", now), false, now)
	}
	if _, retry := l.Allow("alice", "192.0.2.1", now); retry != 250*time.Millisecond {
		t.Fatalf("initial retry=%v", retry)
	}
	now = now.Add(250 * time.Millisecond)
	l.Result(admit(t, l, "alice", "192.0.2.1", now), false, now)
	if _, retry := l.Allow("alice", "192.0.2.1", now); retry != 500*time.Millisecond {
		t.Fatalf("doubled retry=%v", retry)
	}
	now = now.Add(500 * time.Millisecond)
	l.Result(admit(t, l, "alice", "192.0.2.1", now), true, now)
	admit(t, l, "alice", "192.0.2.1", now)
}

func TestAuthLimiterProofChecksIdentityBackoff(t *testing.T) {
	t.Parallel()
	for _, identity := range []string{"IP", "username"} {
		t.Run(identity, func(t *testing.T) {
			t.Parallel()
			testAuthProofIdentityBackoff(t, identity)
		})
	}
}

func testAuthProofIdentityBackoff(t *testing.T, identity string) {
	t.Helper()
	l := New(Config{GlobalBurst: 4, GlobalInterval: time.Hour})
	now := time.Now()
	query := admit(t, l, "alice", "192.0.2.1", now)
	username, ip := "alice", differentSource(t, l, "192.0.2.1")
	if identity == "IP" {
		username, ip = differentUsername(t, l, "alice"), "192.0.2.1"
	}
	var failures [3]Attempt
	for i := range failures {
		failures[i] = admit(t, l, username, ip, now)
	}
	if retry := l.RetryBackoff(query, now); retry != 0 {
		t.Fatalf("proof charged another token: %v", retry)
	}
	for _, attempt := range failures {
		l.Result(attempt, false, now)
	}
	if retry := l.RetryBackoff(query, now); retry != 250*time.Millisecond {
		t.Fatalf("proof ignored %s backoff: %v", identity, retry)
	}
}

func TestAuthLimiterInvalidAttempts(t *testing.T) {
	t.Parallel()
	l := New(Config{})
	now := time.Now()
	foreign := admit(t, New(Config{}), "alice", "192.0.2.1", now)
	for _, attempt := range []Attempt{{}, foreign, {owner: l, ip: l.ipCount}} {
		l.Result(attempt, false, now)
		if retry := l.RetryBackoff(attempt, now); retry <= 0 {
			t.Fatal("invalid attempt admitted a proof")
		}
	}
	if !l.lastTime.IsZero() {
		t.Fatal("invalid result changed limiter state")
	}
	invalid := New(Config{MaxEntries: 1})
	if _, retry := invalid.Allow("u", "192.0.2.1", now); retry <= 0 {
		t.Fatal("invalid one-slot configuration admitted authentication")
	}
	if invalid.ipCount+invalid.userCount != 1 {
		t.Fatal("invalid capacity was silently enlarged")
	}
}

func TestAuthLimiterConcurrentAdmission(t *testing.T) {
	t.Parallel()
	l := New(Config{GlobalBurst: 32, IPBurst: 32, UserBurst: 32})
	now := time.Now()
	admitted := make(chan Attempt, 128)
	var group sync.WaitGroup
	for range cap(admitted) {
		group.Go(func() {
			if attempt, retry := l.Allow("alice", "192.0.2.1", now); retry == 0 {
				admitted <- attempt
			}
		})
	}
	group.Wait()
	close(admitted)
	if len(admitted) != 32 {
		t.Fatalf("concurrent admissions = %d, want 32", len(admitted))
	}
	for attempt := range admitted {
		group.Go(func() { l.Result(attempt, true, now) })
	}
	group.Wait()
}

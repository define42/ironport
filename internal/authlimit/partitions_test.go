package authlimit

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func TestAuthLimiterSaturationKeepsAdmitting(t *testing.T) {
	t.Parallel()
	for _, capacity := range []int{2, 3, 16} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			t.Parallel()
			l := New(Config{MaxEntries: capacity, GlobalBurst: 1001, IPBurst: 1001, UserBurst: 1001})
			now := time.Now()
			for i := range 1000 {
				admit(t, l, fmt.Sprintf("user%d", i), fmt.Sprintf("198.51.%d.%d", i/256, i%256), now)
			}
			admit(t, l, "legitimate", "203.0.113.1", now)
			if got := len(l.ips) + len(l.users); got > capacity {
				t.Fatalf("retained %d slots, capacity %d", got, capacity)
			}
			if l.ipCount != capacity/2 || l.ipCount+l.userCount != capacity {
				t.Fatal("partition sizes do not preserve the configured bound")
			}
		})
	}
}

func TestAuthLimiterArbitraryNamesRemainBounded(t *testing.T) {
	t.Parallel()
	l := New(Config{GlobalBurst: 10001, IPBurst: 10001, UserBurst: 10001})
	now := time.Now()
	for i := range 10000 {
		admit(t, l, fmt.Sprintf("unknown%d", i), fmt.Sprintf("198.51.%d.%d", i/256, i%256), now)
	}
	if len(l.users) == 0 || len(l.users) > l.userCount || len(l.ips) > l.ipCount {
		t.Fatalf("unbounded username state: sources=%d users=%d", len(l.ips), len(l.users))
	}
	admit(t, l, "legitimate", "203.0.113.1", now)
}

func TestAuthLimiterSuppliedUsernameRetainsBackoff(t *testing.T) {
	t.Parallel()
	l := New(Config{})
	now := time.Now()
	var pending [3]Attempt
	for i := range pending {
		pending[i] = admit(t, l, "candidate", "192.0.2.1", now)
	}
	freshIP := differentSource(t, l, "192.0.2.1")
	proof := admit(t, l, "candidate", freshIP, now)
	for _, attempt := range pending {
		l.Result(attempt, false, now)
	}
	if retry := l.RetryBackoff(proof, now); retry != 250*time.Millisecond {
		t.Fatalf("proof lost the supplied username's backoff: %v", retry)
	}
	if _, retry := l.Allow("candidate", freshIP, now); retry != 250*time.Millisecond {
		t.Fatalf("a fresh source bypassed username backoff: %v", retry)
	}
}

func TestAuthLimiterLargeCapacityAllocatesLazily(t *testing.T) {
	t.Parallel()
	l := New(Config{MaxEntries: math.MaxInt})
	if len(l.ips) != 0 || len(l.users) != 0 {
		t.Fatal("construction allocated identity buckets")
	}
	admit(t, l, "alice", "192.0.2.1", time.Now())
	if len(l.ips) != 1 || len(l.users) != 1 {
		t.Fatal("one admission allocated more than two buckets")
	}
}

func TestSourceIdentity(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"192.0.2.1": "192.0.2.1", "::ffff:192.0.2.1": "192.0.2.1",
		"2001:db8:1:2:abcd::1": "2001:db8:1:2::/64", "2001:db8:1:3::1": "2001:db8:1:3::/64",
		"fe80::1%eth0": "fe80::/64", "fe80::2%eth1": "fe80::/64",
		"": "unknown", "not-an-ip": "unknown",
	} {
		if got := sourceIdentity(input); got != want {
			t.Errorf("sourceIdentity(%q) = %q, want %q", input, got, want)
		}
	}
}

package engine

import "testing"

func TestDedupTracker_EdgeContextAffectsUniqueness(t *testing.T) {
	d := NewDedupTracker()

	if d.Check("node-1", "ip=1.1.1.1|port=443", "httpx_probe") {
		t.Fatal("unexpected initial duplicate")
	}

	d.Mark("node-1", "ip=1.1.1.1|port=443", "httpx_probe")

	if !d.Check("node-1", "ip=1.1.1.1|port=443", "httpx_probe") {
		t.Fatal("expected duplicate after mark with same edge context")
	}

	if d.Check("node-1", "ip=2.2.2.2|port=443", "httpx_probe") {
		t.Fatal("different edge context should not dedupe")
	}
}

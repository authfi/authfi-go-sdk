package authfi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestReceiptToRefusalLatency measures, over 50 runs against a real HTTP listener, the time from
// the transmitter starting a push to Verify refusing a token the SET covers. The transmitter is a
// stand-in that signs and POSTs the SET exactly as the platform's does; the platform-side delay
// before the push (the drain) is not part of this number.
func TestReceiptToRefusalLatency(t *testing.T) {
	g := newRig(t)
	srv := httptest.NewServer(g.r)
	defer srv.Close()

	const runs = 50
	httpc := &http.Client{Timeout: 5 * time.Second}
	var total, handler []time.Duration
	for i := 0; i < runs; i++ {
		sub := fmt.Sprintf("agent:agt_lat_%d", i)
		tok := g.tokenFor(sub, g.f.clock().Add(-time.Second), nil)
		if err := g.verify(tok); err != nil {
			t.Fatalf("run %d: before: %v", i, err)
		}
		c := g.f.goodSET(evSessionRevoked, nil)
		c["sub_id"] = map[string]any{"format": "opaque", "id": sub}
		c["jti"] = fmt.Sprintf("lat-%d", i)
		set := g.f.mintSET(setSpec{claims: c})

		start := time.Now()
		req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(set))
		req.Header.Set("Content-Type", secevent)
		resp, err := httpc.Do(req)
		if err != nil || resp.StatusCode != http.StatusAccepted {
			t.Fatalf("run %d: push: %v %v", i, err, resp)
		}
		resp.Body.Close()
		_, verr := g.c.Verify(context.Background(), tok)
		d := time.Since(start)
		mustCode(t, verr, CodeRevoked)
		total = append(total, d)

		hs := time.Now()
		w := httptest.NewRecorder()
		rq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(g.f.mintSET(setSpec{claims: withJTI(c, fmt.Sprintf("lat-h-%d", i))})))
		rq.Header.Set("Content-Type", secevent)
		g.r.ServeHTTP(w, rq)
		handler = append(handler, time.Since(hs))
	}
	sum := func(name string, ds []time.Duration) string {
		s := append([]time.Duration(nil), ds...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		var tot time.Duration
		for _, d := range s {
			tot += d
		}
		return fmt.Sprintf("%-34s n=%d min=%v p50=%v p95=%v p99=%v max=%v mean=%v", name, len(s), s[0], s[len(s)/2], s[len(s)*95/100], s[len(s)*99/100], s[len(s)-1], tot/time.Duration(len(s)))
	}
	out := "Go SDK receiver: push start to Verify refusal, loopback HTTP, 50 runs\n" +
		sum("push -> refused (HTTP + handler)", total) + "\n" +
		sum("handler only (in-process)", handler) + "\n" +
		"Excludes the transmitter's queue and drain delay; that part is measured on the platform side.\n"
	t.Log("\n" + out)
	if p := os.Getenv("LATENCY_OUT"); p != "" {
		if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := append([]time.Duration(nil), total...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if s[len(s)*99/100] > time.Second {
		t.Fatalf("p99 %v is not under 1s", s[len(s)*99/100])
	}
}

func withJTI(c map[string]any, jti string) map[string]any {
	out := make(map[string]any, len(c))
	for k, v := range c {
		out[k] = v
	}
	out["jti"] = jti
	return out
}

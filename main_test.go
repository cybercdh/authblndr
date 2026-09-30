package main

import (
	"strings"
	"testing"
)

func TestNeedsAuthProbe(t *testing.T) {
	yes := []int{401, 403, 300, 301, 302, 307, 308, 399}
	no := []int{200, 204, 400, 404, 429, 500, 502}
	for _, c := range yes {
		if !needsAuthProbe(c) {
			t.Errorf("needsAuthProbe(%d) = false, want true", c)
		}
	}
	for _, c := range no {
		if needsAuthProbe(c) {
			t.Errorf("needsAuthProbe(%d) = true, want false", c)
		}
	}
}

func TestIsSuccess(t *testing.T) {
	for _, c := range []int{200, 201, 204, 299} {
		if !isSuccess(c) {
			t.Errorf("isSuccess(%d) = false, want true", c)
		}
	}
	for _, c := range []int{199, 300, 301, 401, 500} {
		if isSuccess(c) {
			t.Errorf("isSuccess(%d) = true, want false", c)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate short = %q", got)
	}
	got := truncate("hello world", 5)
	if !strings.HasPrefix(got, "hello") || !strings.HasSuffix(got, "…") {
		t.Errorf("truncate long = %q", got)
	}
}

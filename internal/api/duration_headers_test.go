package api

import (
	"testing"
	"time"
)

func TestRetryAfterSeconds(t *testing.T) {
	tests := []struct {
		name  string
		delay time.Duration
		want  string
	}{
		{name: "negative", delay: -time.Second, want: "0"},
		{name: "zero", delay: 0, want: "0"},
		{name: "sub_second_ceil", delay: 500 * time.Millisecond, want: "1"},
		{name: "exact_second", delay: 2 * time.Second, want: "2"},
		{name: "partial_second_ceil", delay: 2*time.Second + time.Nanosecond, want: "3"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryAfterSeconds(tc.delay); got != tc.want {
				t.Fatalf("retryAfterSeconds(%v) = %q, want %q", tc.delay, got, tc.want)
			}
		})
	}
}

func TestCookieMaxAgeSeconds(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want int
	}{
		{name: "negative", ttl: -time.Second, want: 0},
		{name: "zero", ttl: 0, want: 0},
		{name: "sub_second_ceil", ttl: 500 * time.Millisecond, want: 1},
		{name: "partial_second_ceil", ttl: 2*time.Second + time.Nanosecond, want: 3},
		{name: "whole_seconds", ttl: 24 * time.Hour, want: 86400},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cookieMaxAgeSeconds(tc.ttl); got != tc.want {
				t.Fatalf("cookieMaxAgeSeconds(%v) = %d, want %d", tc.ttl, got, tc.want)
			}
		})
	}
}

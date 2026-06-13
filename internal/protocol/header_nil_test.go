package protocol

import (
	"strings"
	"testing"
)

func TestHeaderNilReceiverSafe(t *testing.T) {
	var h *Header
	buf := make([]byte, HeaderLen)

	if err := h.Pack(buf); err == nil || !strings.Contains(err.Error(), "nil header") {
		t.Fatalf("nil Header Pack() error = %v, want nil header error", err)
	}
	if err := h.Unpack(buf); err == nil || !strings.Contains(err.Error(), "nil header") {
		t.Fatalf("nil Header Unpack() error = %v, want nil header error", err)
	}
	if got := h.String(); got != "<nil header>" {
		t.Fatalf("nil Header String() = %q, want nil placeholder", got)
	}

	h.SetResponse(RcodeSuccess)
	h.SetTruncated(true)
	h.SetAuthoritative(true)
	h.ClearCounts()

	if h.IsSuccess() {
		t.Fatal("nil Header IsSuccess() = true, want false")
	}
	if got := h.Copy(); got != nil {
		t.Fatalf("nil Header Copy() = %#v, want nil", got)
	}
}

package protocol

import (
	"errors"
	"testing"
)

func TestBufferNilReceiverSafe(t *testing.T) {
	var b *Buffer

	b.Reset()
	if got := b.Data(); got != nil {
		t.Fatalf("nil Buffer Data() = %#v, want nil", got)
	}
	if got := b.Bytes(); got != nil {
		t.Fatalf("nil Buffer Bytes() = %#v, want nil", got)
	}
	if got := b.Length(); got != 0 {
		t.Fatalf("nil Buffer Length() = %d, want 0", got)
	}
	if got := b.Capacity(); got != 0 {
		t.Fatalf("nil Buffer Capacity() = %d, want 0", got)
	}
	if got := b.Offset(); got != 0 {
		t.Fatalf("nil Buffer Offset() = %d, want 0", got)
	}
	if got := b.Remaining(); got != 0 {
		t.Fatalf("nil Buffer Remaining() = %d, want 0", got)
	}
	if got := b.Available(); got != 0 {
		t.Fatalf("nil Buffer Available() = %d, want 0", got)
	}

	if err := b.SetOffset(0); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer SetOffset() error = %v, want ErrNilBuffer", err)
	}
	if err := b.WriteUint8(0); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer WriteUint8() error = %v, want ErrNilBuffer", err)
	}
	if err := b.WriteUint16(0); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer WriteUint16() error = %v, want ErrNilBuffer", err)
	}
	if err := b.WriteUint32(0); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer WriteUint32() error = %v, want ErrNilBuffer", err)
	}
	if err := b.WriteBytes([]byte{1}); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer WriteBytes() error = %v, want ErrNilBuffer", err)
	}
	if _, err := b.ReadUint8(); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer ReadUint8() error = %v, want ErrNilBuffer", err)
	}
	if _, err := b.ReadUint16(); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer ReadUint16() error = %v, want ErrNilBuffer", err)
	}
	if _, err := b.ReadUint32(); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer ReadUint32() error = %v, want ErrNilBuffer", err)
	}
	if _, err := b.ReadBytes(1); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer ReadBytes() error = %v, want ErrNilBuffer", err)
	}
	if _, err := b.PeekUint16(); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer PeekUint16() error = %v, want ErrNilBuffer", err)
	}
	if err := b.Skip(1); !errors.Is(err, ErrNilBuffer) {
		t.Fatalf("nil Buffer Skip() error = %v, want ErrNilBuffer", err)
	}
}

func TestBufferRejectsNegativeLengths(t *testing.T) {
	b := NewBufferFromData([]byte{1, 2, 3})

	if _, err := b.ReadBytes(-1); !errors.Is(err, ErrInvalidOffset) {
		t.Fatalf("ReadBytes(-1) error = %v, want ErrInvalidOffset", err)
	}
	if got := b.Offset(); got != 0 {
		t.Fatalf("offset after ReadBytes(-1) = %d, want 0", got)
	}

	if err := b.Skip(-1); !errors.Is(err, ErrInvalidOffset) {
		t.Fatalf("Skip(-1) error = %v, want ErrInvalidOffset", err)
	}
	if got := b.Offset(); got != 0 {
		t.Fatalf("offset after Skip(-1) = %d, want 0", got)
	}
}

func TestNewBufferFromDataCopiesInput(t *testing.T) {
	data := []byte{1, 2, 3}
	b := NewBufferFromData(data)

	data[0] = 9

	got, err := b.ReadBytes(3)
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if got[0] != 1 {
		t.Fatalf("buffer aliases input data: got first byte %d", got[0])
	}

	internal := b.Data()
	internal[1] = 8
	if data[1] == 8 {
		t.Fatal("buffer data aliases input slice")
	}
}

func TestWireUintHelpersShortSlicesSafe(t *testing.T) {
	PutUint16(nil, 0x1234)
	PutUint16([]byte{0}, 0x1234)
	PutUint32(nil, 0x12345678)
	PutUint32([]byte{0, 1, 2}, 0x12345678)

	if got := Uint16(nil); got != 0 {
		t.Fatalf("Uint16(nil) = %d, want 0", got)
	}
	if got := Uint16([]byte{1}); got != 0 {
		t.Fatalf("Uint16(short) = %d, want 0", got)
	}
	if got := Uint32(nil); got != 0 {
		t.Fatalf("Uint32(nil) = %d, want 0", got)
	}
	if got := Uint32([]byte{1, 2, 3}); got != 0 {
		t.Fatalf("Uint32(short) = %d, want 0", got)
	}
}

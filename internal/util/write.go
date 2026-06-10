package util

import "io"

// WriteFull writes all of p to w, retrying on short writes. It returns a
// non-nil error if fewer than len(p) bytes could be written. A Write that
// returns 0, nil is treated as io.ErrNoProgress to avoid spinning forever.
func WriteFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

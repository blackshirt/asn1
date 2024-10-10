module asn1

import io

// Port and translates of of golang bytes.Buffer to v

const small_buffer_size = 64

struct Buffer {
	buf       []u8
	off       int
	last_read read_op
}

type read_op = i8

const op_read = read_op(-1) // Any other read operation.

const op_invalid = read_op(0) // Non-read operation.

const op_read_rune1 = read_op(1) // Read rune of size 1.

const op_read_rune2 = read_op(2) // Read rune of size 2.

const op_read_rune3 = read_op(3) // Read rune of size 3.

const op_read_rune4 = read_op(4) // Read rune of size 4.

const err_too_large = error('Buffer: too large')
const err_negative_read = error('Buffer: reader returned negative count from Read')

fn (b Buffer) bytes() []u8 {
	return b.buf[b.off..]
}

fn (b Buffer) available_buffer() []u8 {
	return b.buf[b.buf.len..]
}

fn (b Buffer) str() string {
	if b.buf[b.off..].len == 0 {
		return '<nil>'
	}
	return b.buf[b.off..].str()
}

fn (b Buffer) empty() bool {
	return b.buf.len <= b.off
}

fn (b Buffer) len() int {
	return b.buf.len - b.off
}

fn (b Buffer) cap() int {
	return b.buf.cap
}

fn (b Buffer) available() int {
	return b.buf.cap - b.buf.len
}

fn (b Buffer) truncate(n int) {
	if n == 0 {
		b.reset()
		return
	}
	b.last_read = op_invalid
	if n < 0 || n > b.len() {
		panic('bytes.Buffer: truncation out of range')
	}
	b.buf = unsafe { b.buf[..b.off + n] }
}

fn (b Buffer) reset() {
	b.buf = unsafe { b.buf[..0] }
	b.off = 0
	b.last_read = op_invalid
}

fn (b Buffer) try_grow_by_reslice(n int) (int, bool) {
	x := b.buf.len
	if n <= b.buf.cap - x {
		b.buf = unsafe { b.buf[..x + n] }
		return x, true
	}
	return 0, false
}

fn (b Buffer) generic_grow(n int) int {
	m := b.len()
	if m == 0 && b.off != 0 {
		b.reset()
	}
	// Try to grow by means of a reslice.
	i, ok := b.try_grow_by_reslice(n)
	if ok {
		return i
	}
	// b.buf.len == 0 ?
	if b.buf == unsafe { nil } && n <= small_buffer_size {
		b.buf = []u8{len: n, cap: small_buffer_size}
		return 0
	}
	c := b.buf.cap
	if n <= c / 2 - m {
		// copy(mut dst []u8, src []u8) int
		_ := copy(mut b.buf, b.buf[b.off..])
	} else if c > max_int - c - n {
		panic(err_too_large)
	} else {
		b.buf = unsafe { grow_slice(b.buf[b.off..], b.off + n) }
	}
	// Restore b.off and b.buf.len.
	b.off = 0
	b.buf = unsafe { b.buf[..m + n] }
	return m
}

fn (b Buffer) grow(n int) {
	if n < 0 {
		panic('bytes.Buffer.Grow: negative count')
	}
	m := b.generic_grow(n)
	b.buf = unsafe { b.buf[..m] }
}

fn (b Buffer) write(p []u8) !int {
	b.last_read = op_invalid
	mut m, ok := b.try_grow_by_reslice(len(p))
	if !ok {
		m = b.generic_grow(len(p))
	}
	n := copy(mut b.buf[m..], p)
	return n
}

fn (b Buffer) write_string(s string) !int {
	b.last_read = op_invalid
	m, ok := b.try_grow_by_reslice(len(s))
	if !ok {
		m = b.generic_grow(len(s))
	}
	return copy(b.buf[m..], s)
}

const min_read = 512

fn (b Buffer) read_from(r io.Reader) !i64 {
	b.last_read = op_invalid
	mut n := 0
	for {
		i := b.generic_grow(min_read)
		b.buf = b.buf[..i]
		// read(mut buf []u8) !int
		m := r.read(mut b.buf[i..b.buf.cap]) or { return n }
		if m < 0 {
			panic(err_negative_read)
		}

		b.buf = unsafe { b.buf[..i + m] }
		n += i64(m)
		return n
	}
}

// grow_slice grows b by n, preserving the original content of b.
// If the allocation fails, it panics with err_too_large.
fn grow_slice(b []u8, n int) []u8 {
	// recover not supported

	c := len(b) + n // ensure enough space for n elements
	if c < 2 * b.cap {
		// The growth rate has historically always been 2x. In the future,
		// we could rely purely on append to determine the growth rate.
		c = 2 * b.cap
	}
	temp := []u8{len: c}
	mut b2 := []u8{}
	b2 << temp
	_ := copy(mut b2, b)
	return b2[..b.len]
}

fn (b Buffer) write_to(w io.Writer) !i64 {
	mut n := i64(0)
	b.last_read = op_invalid
	nbytes := b.len()
	if nbytes > 0 {
		// write(buf []u8) !int
		m := w.write(b.buf[b.off..]) or { return n }
		if m > nbytes {
			panic('bytes.Buffer.WriteTo: invalid Write count')
		}
		b.off += m
		n = i64(m)

		// all bytes should have been written, by definition of
		// Write method in io.Writer
		if m != nbytes {
			return error('io.ErrShortWrite')
		}
	}
	// Buffer is now empty; reset.
	b.reset()
	return n
}

fn (b Buffer) write_byte(c byte) ! {
	b.last_read = op_invalid
	m, ok := b.try_grow_by_reslice(1)
	if !ok {
		m = b.generic_grow(1)
	}
	b.buf[m] = c
}

/*
fn (b Buffer) write_rune(r rune) !int {
	// Compare as uint32 to correctly handle negative runes.
	if uint32(r) < utf8.RuneSelf {
		b.write_byte(byte(r))
		return 1, nil
	}
	b.last_read = op_invalid
	m, ok := b.try_grow_by_reslice(utf8.UTFMax)
	if !ok {
		m = b.generic_grow(utf8.UTFMax)
	}
	b.buf = utf8.AppendRune(b.buf[:m], r)
	return b.buf.len - m, nil
} */

fn (b Buffer) read(p []u8) !int {
	b.last_read = op_invalid
	if b.empty() {
		// Buffer is empty, reset to recover space.
		b.reset()
		if p.len == 0 {
			return 0
		}
		return io.EOF
	}
	n = copy(mut p, b.buf[b.off..])
	b.off += n
	if n > 0 {
		b.last_read = op_read
	}
	return n
}

fn (b Buffer) next(n int) []u8 {
	b.last_read = op_invalid
	m := b.len()
	if n > m {
		n = m
	}
	data := b.buf[b.off..b.off + n]
	b.off += n
	if n > 0 {
		b.last_read = op_read
	}
	return data
}

fn (b Buffer) read_byte() !u8 {
	if b.empty() {
		// Buffer is empty, reset to recover space.
		b.reset()
		return io.EOF
	}
	c := b.buf[b.off]
	b.off++
	b.last_read = op_read
	return c
}

/* fn (b Buffer) read_rune() !(rune, int) {
	if b.empty() {
		// Buffer is empty, reset to recover space.
		b.reset()
		return 0, 0, io.EOF
	}
	c := b.buf[b.off]
	if c < utf8.RuneSelf {
		b.off++
		b.last_read = op_read_rune1
		return rune(c), 1, nil
	}
	r, n := utf8.DecodeRune(b.buf[b.off..])
	b.off += n
	b.last_read = read_op(n)
	return r, n, nil
}


fn (b Buffer) unread_rune() error {
	if b.last_read <= op_invalid {
		return errors.New("bytes.Buffer: unread_rune: previous operation was not a successful read_rune")
	}
	if b.off >= int(b.last_read) {
		b.off -= int(b.last_read)
	}
	b.last_read = op_invalid
	return nil
} */

const err_unread_byte = error('bytes.Buffer: unread_byte: previous operation was not a successful read')

fn (b Buffer) unread_byte() ! {
	if b.last_read == op_invalid {
		return err_unread_byte
	}
	b.last_read = op_invalid
	if b.off > 0 {
		b.off--
	}
}

/* fn (b Buffer) read_bytes(delim byte) ![]u8 {
	slice := b.read_slice(delim)!
	// return a copy of slice. The buffer's backing array may
	// be overwritten by later calls.
	line = append(line, slice...)
	return line, err
}

fn (b Buffer) read_slice(delim byte) ![]u8 {
	i := IndexByte(b.buf[b.off..], delim)
	end := b.off + i + 1
	if i < 0 {
		end = b.buf.len
		err = io.EOF
	}
	line = b.buf[b.off..end]
	b.off = end
	b.last_read = op_read
	return line, err
}

fn (b Buffer) read_string(delim byte) !string {
	slice, err := b.read_slice(delim)
	return string(slice), err
} */

fn new_buffer(buf []u8) &Buffer {
	return &Buffer{
		buf: buf
	}
}

fn new_buffer_string(s string) &Buffer {
	return &Buffer{
		buf: s.bytes()
	}
}

// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

pub fn base128_int_length(v i64) int {
	mut n := v
	mut ret := 0

	for n > 0 {
		ret += 1
		n >>= 7
	}

	return ret
}

// encode_base128_int serialize integer to bytes in base 128 integer.
pub fn encode_base128_int(mut dst []u8, n i64) []u8 {
	if n == 0 {
		dst << u8(0x00)
		return dst
	}
	l := base128_int_length(n)

	for i := l - 1; i >= 0; i-- {
		mut o := u8(n >> u32(i * 7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}

		dst << o
	}

	return dst
}

// decode_base128_int read bytes as base 128 integer for current position `loc`.
// Its returns integer value and next offset to read from.
pub fn decode_base128_int(bytes []u8, loc int) !(int, int) {
	mut pos := loc
	mut r64 := i64(0)
	mut ret := 0
	for s := 0; pos < bytes.len; s++ {
		r64 <<= 7
		b := bytes[pos]

		if s == 0 && b == 0x80 {
			return error('integer is not minimaly encoded')
		}

		r64 |= i64(b & 0x7f)
		pos += 1

		if b & 0x80 == 0 {
			ret = int(r64)
			if r64 > max_i32 {
				return error('base 128 integer too large')
			}
			return ret, pos
		}
	}
	return error('truncated base 128 integer')
}

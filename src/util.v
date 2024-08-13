// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 Utility function

// read_bytes was safe version of bytes slicing, `src[pos..pos+size]`
pub fn read_bytes(src []u8, pos int, size int) ![]u8 {
	if src.len < 1 || pos > src.len || size > src.len {
		return error(' pos=${pos} or size=${size} bigger than len=${src.len}')
	}
	if pos + size > src.len {
		return error('pos + size maybe getting overflow')
	}

	ret := src[pos..pos + size]
	return ret
}

pub fn read_byte(src []u8, loc int) !(u8, int) {
	if src.len == 0 || loc > src.len - 1 {
		return error('invalid loc or len')
	}

	mut pos := loc
	result := src[pos]
	pos += 1

	return result, pos
}

fn read_digit(src []u8, loc int) !(u8, int) {
	val, pos := read_byte(src, loc)!
	// check its a digit, '0'-'9',
	// aka, 0x30 s/d 0x39 in hex, or 48-57 in dec
	if !val.is_digit() {
		return error('not digit byte')
	}

	digit := val - u8(0x30) // get the digit value
	return digit, pos
}

fn read_2_digits(src []u8, loc int) !(u8, int) {
	if loc >= src.len || src.len - loc < 2 {
		return error('not enough bytes')
	}
	mut val, mut pos := read_digit(src, loc)!

	first := val * 10

	if pos < src.len {
		val, pos = read_digit(src, pos)!
	}
	return first + val, pos
}

fn read_4_digits(src []u8, loc int) !(u16, int) {
	if loc >= src.len || src.len - loc < 4 {
		return error('not enough bytes')
	}
	mut val, mut pos := read_digit(src, loc)!
	first := u16(val) * 1000

	if pos < src.len {
		val, pos = read_digit(src, pos)!
	}
	second := u16(val) * 100

	if pos < src.len {
		val, pos = read_digit(src, pos)!
	}
	third := u16(val) * 10

	if pos < src.len {
		val, pos = read_digit(src, pos)!
	}
	fourth := u16(val)

	result := first + second + third + fourth
	return result, pos
}

fn validate_date(year u16, month u8, day u8) bool {
	if year < 0 {
		return false
	}
	if day < 1 {
		return false
	}
	mut dim := month
	match month {
		1, 3, 5, 7, 8, 10, 12 {
			dim = 31
		}
		4, 6, 9, 11 {
			dim = 30
		}
		2 {
			// kabisat
			if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
				dim = 29
			} else {
				dim = 28
			}
		}
		else {
			return false
		}
	}
	if day > dim {
		return false
	}

	return true
}

fn base128_int_length(v i64) int {
	mut n := v
	mut ret := 0

	for n > 0 {
		ret += 1
		n >>= 7
	}

	return ret
}

// encode_base128_int serialize integer to bytes in base 128 integer.
fn encode_base128_int(mut dst []u8, n i64) []u8 {
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
fn decode_base128_int(bytes []u8, loc int) !(int, int) {
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

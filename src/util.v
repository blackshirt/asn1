// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 Utility function

// read_bytes was safe version of bytes slicing, `src[pos..pos+size]`
fn read_bytes(src []u8, pos int, size int) ![]u8 {
	if src.len < 1 || pos > src.len || size > src.len {
		return error(' pos=${pos} or size=${size} bigger than len=${src.len}')
	}
	if pos + size > src.len {
		return error('pos + size maybe getting overflow')
	}

	ret := src[pos..pos + size]
	return ret
}

fn read_byte(src []u8, loc int) !(u8, int) {
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


/*
// calculate lenght of bytes needed to store n
fn calc_length(n int) int {
	mut i := n
	mut num := 1
	for i > 255 {
		num++
		i >>= 8
	}
	return num
}

		
// bytes part of the length
fn append_length(mut dst []u8, i int) []u8 {
	mut n := calc_length(i)

	for ; n > 0; n-- {
		dst << u8(i >> (n - 1) * 8)
	}

	return dst
}

		
// calculates length of length bytes
fn calc_length_of_length(value int) int {
	mut length := 1
	if value >= 128 {
		s := calc_length(value)
		// length += 1
		length += s
	}
	return length
}


// serialize_length encodes value to dst
fn serialize_length(mut dst []u8, value int) []u8 {
	// mut dst := []u8{}
	// long form
	if value >= 128 {
		length := calc_length(value)
		dst << 0x80 | u8(length)
		dst = append_length(mut dst, value)
	} else {
		// short form
		dst << u8(value)
	}

	return dst
}

// decode_length decodes bytes from positon `loc` and returns integer length value and
// next offset to read bytes data from.
fn decode_length(buf []u8, loc int) !(int, int) {
	mut pos := loc
	if pos >= buf.len {
		return error('truncated tag or length')
	}
	mut b := buf[pos]
	pos += 1
	mut length := 0
	if b & 0x80 == 0 {
		length = int(b & 0x7f)
	} else {
		num_bytes := b & 0x7f
		if num_bytes == 0 {
			return error('unsupported undefinite length')
		}

		for i := 0; i < num_bytes; i++ {
			if pos >= buf.len {
				return error('truncated tag or length')
			}
			b = buf[pos]
			pos += 1
			if length > (max_i64 >> 8) {
				return error('Length: integer overflow')
			}
			length <<= 8
			length |= int(b)
			if length == 0 {
				return error('leading zeros')
			}
		}

		// do not allow values <0x80 to be encoded in long form
		if length < 0x80 {
			// dump(length)
			return error('dont needed in long form')
		}
	}
	return length, pos
}


// `serialize_tag` return bytes of serialized tag.
// This routine supports multi byte tag form to represents tag value that bigger than 31 (0x1f).
fn serialize_tag(mut dst []u8, tag Tag) []u8 {
	mut b := u8(tag.cls) << 6
	if tag.compound {
		b |= compound_mask
	}

	if tag.value >= 0x1f {
		b |= tag_mask // 0x1f
		dst << b
		dst = encode_base128_int(mut dst, i64(tag.value))
	} else {
		b |= u8(tag.value)
		dst << b
	}

	return dst
}

// `read_tag` reading bytes of data from location (offset) `loc` to tag.
// It's return the tag structure and the next position (offset) `pos` for reading the length part.
fn read_tag(data []u8, loc int) !(Tag, int) {
	if data.len < 1 {
		return error('get ${data.len} bytes for reading tag, its not enough')
	}
	mut pos := loc
	if pos > data.len {
		return error('invalid len')
	}

	b := data[pos]
	pos += 1

	mut value := int(b & tag_mask)
	compound := b & compound_mask == compound_mask
	cls := int(b >> 6)

	if value == 0x1f {
		// we mimic go version of tag handling, only allowed `max_tag_length` bytes following
		// to represent tag value.
		value, pos = decode_base128_int(data, pos)!
		// pos is the next position to read next bytes, so check tag bytes length
		if (pos - loc - 1) >= asn1.max_tag_length {
			return error('tag bytes is too big')
		}
		if value < 0x1f {
			return error('non-minimal tag')
		}
	}
	tag := Tag{
		// casting numbers to enums, should be done inside `unsafe{}` blocks
		cls: unsafe { Class(cls) }
		compound: compound
		value: value
	}
	return tag, pos
}
*/
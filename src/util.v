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

fn valid_integer(src []u8, signed bool) bool {
	if src.len == 0 {
		return false
	}

	// check for minimaly encoded
	if src.len > 1 && ((src[0] == 0 && src[1] & 0x80 == 0)
		|| (src[0] == 0xff && src[1] & 0x80 == 0x80)) {
		return false
	}

	// reject negative for unsigned type
	if !signed && src[0] & 0x80 == 0x80 {
		return false
	}
	return true
}

// i64 handling

// serialize i64
fn serialize_i64(s i64) ![]u8 {
	t := new_tag(.universal, false, int(TagType.integer))
	mut out := []u8{}

	serialize_tag(mut out, t)

	n := length_i64(s)
	mut src := []u8{len: n}

	i64_to_bytes(mut src, s)
	serialize_length(mut out, src.len)
	out << src
	return out
}

fn decode_i64(src []u8) !(Tag, i64) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.integer) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	// mut length := 0
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!

	val := read_i64(out)!

	return tag, val
}

// read_i64 read src as signed i64
fn read_i64(src []u8) !i64 {
	if !valid_integer(src, true) {
		return error('i64 check return false')
	}
	mut ret := i64(0)

	if src.len > 8 {
		return error('too large integer')
	}
	for i := 0; i < src.len; i++ {
		ret <<= 8
		ret |= i64(src[i])
	}

	ret <<= 64 - u8(src.len) * 8
	ret >>= 64 - u8(src.len) * 8

	// try to serialize back, and check its matching original one
	// and gives a warning when its not match.
	$if debug {
		a := new_integer(ret)
		c := a.contents()!
		if c != src {
			eprintln('maybe integer bytes not in shortest form')
		}
	}
	return ret
}

fn length_i64(val i64) int {
	mut i := val
	mut n := 1

	for i > 127 {
		n++
		i >>= 8
	}

	for i < -128 {
		n++
		i >>= 8
	}

	return n
}

fn i64_to_bytes(mut dst []u8, i i64) {
	mut n := length_i64(i)

	for j := 0; j < n; j++ {
		dst[j] = u8(i >> u32((n - 1 - j) * 8))
	}
}

// i32 handling
//
// read_i32 readt  from bytes
fn read_i32(src []u8) !int {
	if !valid_integer(src, true) {
		return error('i32 check return false')
	}

	ret := read_i64(src)!
	if ret != i64(int(ret)) {
		return error('integer too large')
	}

	return int(ret)
}

fn serialize_i32(s i32) ![]u8 {
	out := serialize_i64(i64(s))!
	return out
}

fn decode_i32(src []u8) !(Tag, i32) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.integer) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!
	val := read_i32(out)!

	return tag, val
}
*/

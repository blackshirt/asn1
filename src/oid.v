// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import math

// TODO: doing check for limiting oid array length.
const (
	max_oid_length = 128
)

// ObjectIdentifier
pub type Oid = []int

// new_oid_from_bytes read bytes as ObjectIdentifier
fn new_oid_from_bytes(src []u8) !Encoder {
	oid := read_oid(src)!
	if !validate_oid(oid) {
		return error('bad oid bytes')
	}
	return oid
}

// new_oid_from_string creates Oid serializer from string
pub fn new_oid_from_string(s string) !Encoder {
	values := oid_from_string(s)!
	return values
}

fn oid_from_string(str string) !Oid {
	if str.len < 2 {
		return error('bad string oid length')
	}
	mut result := []int{}
	src := str.split('.')
	for n in src {
		v := n.parse_int(10, 32)!
		result << int(v)
	}
	oid := Oid(result)
	if !validate_oid(oid) {
		return error('bad oid string')
	}
	return oid
}

// new_oid_from_intarray creates Oid serializer from array of int
fn new_oid_from_intarray(src []int) !Encoder {
	oid := oid_from_ints(src)!
	return oid
}

fn oid_from_ints(src []int) !Oid {
	// allowed value of first int was 0, 1 or 2,
	// and when first=2, second int was not limited.
	// contrary, when first < 2, second <= 39
	if src.len < 2 || src[0] > 2 || (src[0] < 2 && src[1] >= 40) {
		return error('bad oid int array')
	}
	// doing check for overflow
	for k in src {
		if k > math.max_i32 {
			return error('overflow parse_int result')
		}
	}
	oid := Oid(src)
	if !validate_oid(oid) {
		return error('bad oid int array')
	}
	return oid
}

fn validate_oid(oid Oid) bool {
	if oid.len > asn1.max_oid_length {
		return false
	}
	if oid.len < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
		return false
	}
	return true
}

fn (oid Oid) tag() Tag {
	return new_tag(.universal, false, int(TagType.oid))
}

fn (oid Oid) length() int {
	return oid_length(oid)
}

fn (oid Oid) size() int {
	mut size := 0
	tag := oid.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(oid.length())
	size += int(l)

	size += oid.length()

	return size
}

fn (oid Oid) encode() ![]u8 {
	return serialize_oid(oid)
}

fn oid_length(oid Oid) int {
	mut n := base128_int_length(i64(oid[0] * 40 + oid[1]))
	for i := 2; i < oid.len; i++ {
		n += base128_int_length(i64(oid[i]))
	}
	return n
}

fn serialize_oid(oid Oid) ![]u8 {
	// TODO: doing oid check validity
	tag := new_tag(.universal, false, int(TagType.oid))
	mut out := []u8{}

	serialize_tag(mut out, tag)
	n := oid_length(oid)
	serialize_length(mut out, n)

	write_oid(mut out, oid)

	return out
}

fn decode_oid(src []u8) !(Tag, Oid) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	// check tag match
	if tag.number != int(TagType.oid) {
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
	// remaining data, ony slicing required parts
	out := read_bytes(src, next, length)!

	oid := read_oid(out)!

	return tag, oid
}

fn read_oid(src []u8) !Oid {
	// maybe two integer fits in 1 bytes
	if src.len < 1 {
		return error('bad string oid length')
	}
	mut s := []int{len: src.len + 1}

	mut val, mut pos := decode_base128_int(src, 0)!

	if val < 80 {
		s[0] = val / 40
		s[1] = val % 40
	} else {
		s[0] = 2
		s[1] = val - 80
	}
	mut i := 2
	for ; pos < src.len; i++ {
		val, pos = decode_base128_int(src, pos)!
		s[i] = val
	}
	s = s[0..i]
	return s
}

fn write_oid(mut dst []u8, oid Oid) []u8 {
	encode_base128_int(mut dst, i64(oid[0] * 40 + oid[1]))
	for i := 2; i < oid.len; i++ {
		encode_base128_int(mut dst, i64(oid[i]))
	}
	return dst
}

fn (oid Oid) equal(oth Oid) bool {
	if oid.len != oth.len {
		return false
	}
	for i := 0; i < oid.len; i++ {
		if oid[i] != oth[i] {
			return false
		}
	}
	return true
}

fn (oid Oid) str() string {
	mut s := []string{}
	for i in oid {
		s << i.str()
	}
	return s.join('.')
}

// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// TODO: doing check for limiting oid array length.
const max_oid_length = 128

// ObjectIdentifier
@[heap; noinit]
pub struct Oid {
mut:
	value []int
}

pub fn (oid Oid) tag() Tag {
	return Tag{.universal, false, int(TagType.oid)}
}

// Oid.new creates new Oid from . separated string
pub fn Oid.new(s string) !Oid {
	if s.len < 2 {
		return error('Oid: bad string oid length')
	}
	mut result := []int{}
	src := s.split('.')
	for n in src {
		v := n.parse_int(10, 32)!
		result << int(v)
	}
	oid := Oid{
		value: result
	}
	if !oid.validate() {
		return error('Oid: bad oid string')
	}
	return oid
}

pub fn Oid.from_ints(src []int) !Oid {
	// allowed value of first int was 0, 1 or 2,
	// and when first=2, second int was not limited.
	// contrary, when first < 2, second <= 39
	if src.len < 2 || src[0] > 2 || (src[0] < 2 && src[1] >= 40) {
		return error('Oid: bad oid int array')
	}
	// doing check for overflow
	for k in src {
		if k > max_i32 {
			return error('Oid: overflow parse_int result')
		}
	}
	oid := Oid{
		value: src
	}
	if !oid.validate() {
		return error('Oid: bad oid int array')
	}
	return oid
}

fn Oid.from_bytes(src []u8) !Oid {
	// maybe two integer fits in 1 bytes
	if src.len == 0 {
		return error('Oid: bad string oid length')
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
	s = unsafe { s[0..i] }

	oid := Oid{
		value: s
	}
	if !oid.validate() {
		return error('Oid: failed to validate')
	}
	return oid
}

pub fn (oid Oid) payload() ![]u8 {
	return oid.pack_into_bytes()!
}

fn (oid Oid) pack_into_bytes() ![]u8 {
	if !oid.validate() {
		return error('Oid: failed to validate')
	}
	mut dst := []u8{}
	// the first two components (a.b) of Oid are encoded as 40*a+b
	encode_base128_int(mut dst, i64(oid.value[0] * 40 + oid.value[1]))
	for i := 2; i < oid.value.len; i++ {
		encode_base128_int(mut dst, i64(oid.value[i]))
	}
	return dst
}

pub fn Oid.parse(mut p Parser) !Oid {
	tag := p.read_tag()!
	if !tag.expect(.universal, false, int(TagType.oid)) {
		return error('Bad Oid tag')
	}
	length := p.read_length()!
	bytes := p.read_bytes(length)!

	res := Oid.from_bytes(bytes)!

	return res
}

pub fn Oid.decode(src []u8) !(Oid, i64) {
	return Oid.decode_with_rule(src, .der)!
}

fn Oid.decode_with_rule(bytes []u8, rule EncodingRule) !(Oid, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, rule)!
	if !tag.expect(.universal, false, int(TagType.oid)) {
		return error('Unexpected non-oid tag')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!
	content := if length == 0 {
		[]u8{}
	} else {
		if content_pos >= bytes.len || content_pos + length > bytes.len {
			return error('Oid: truncated payload bytes')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}

	oid := Oid.from_bytes(content)!
	next := content_pos + length

	return oid, next
}

pub fn (oid Oid) equal(oth Oid) bool {
	if oid.tag != oth.tag {
		return false
	}
	if oid.value.len != oth.value.len {
		return false
	}
	for i := 0; i < oid.value.len; i++ {
		if oid.value[i] != oth.value[i] {
			return false
		}
	}
	return true
}

fn (oid Oid) str() string {
	if oid.value.len == 0 {
		return 'nil'
	}
	mut s := []string{}
	for i in oid.value {
		s << i.str()
	}
	return s.join('.')
}

fn (oid Oid) validate() bool {
	if oid.value.len > max_oid_length {
		return false
	}
	if oid.value.len < 2 || oid.value[0] > 2 || (oid.value[0] < 2 && oid.value[1] >= 40) {
		return false
	}
	return true
}

fn (oid Oid) oid_length() int {
	mut n := base128_int_length(i64(oid.value[0] * 40 + oid.value[1]))
	for i := 2; i < oid.value.len; i++ {
		n += base128_int_length(i64(oid.value[i]))
	}
	return n
}

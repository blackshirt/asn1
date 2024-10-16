// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// TODO: doing check for limiting oid array length.
const max_oid_length = 128
pub const default_oid_tag = Tag{.universal, false, int(TagType.oid)}

// ASN.1 ObjectIdentifier type.
// The ASN. 1 OBJECT IDENTIFIER type is used when you need to provide a unique identifier.
@[noinit]
pub struct ObjectIdentifier {
mut:
	value []int
}

// The tag of ObjectIdentifier type.
pub fn (oid ObjectIdentifier) tag() Tag {
	return default_oid_tag
}

// The payload of ObjectIdentifier type
pub fn (oid ObjectIdentifier) payload() ![]u8 {
	return oid.pack_into_bytes()!
}

// `ObjectIdentifier.new` creates a new ObjectIdentifier type from dots (`.`) separated string.
pub fn ObjectIdentifier.new(s string) !ObjectIdentifier {
	if s.len < 2 {
		return error('ObjectIdentifier: bad string oid length')
	}
	mut result := []int{}
	src := s.split('.')
	for n in src {
		v := n.parse_int(10, 32)!
		result << int(v)
	}
	oid := ObjectIdentifier{
		value: result
	}
	if !oid.validate() {
		return error('ObjectIdentifier: bad oid string')
	}
	return oid
}

// `ObjectIdentifier.from_ints` creates a new ObjectIdentifier type from arrays of int.
pub fn ObjectIdentifier.from_ints(src []int) !ObjectIdentifier {
	// allowed value of first int was 0, 1 or 2,
	// and when first=2, second int was not limited.
	// contrary, when first < 2, second <= 39
	if src.len < 2 || src[0] > 2 || (src[0] < 2 && src[1] >= 40) {
		return error('ObjectIdentifier: bad oid int array')
	}
	// doing check for overflow
	for k in src {
		if k > max_i32 {
			return error('ObjectIdentifier: overflow parse_int result')
		}
	}
	oid := ObjectIdentifier{
		value: src
	}
	if !oid.validate() {
		return error('ObjectIdentifier: bad oid int array')
	}
	return oid
}

fn ObjectIdentifier.from_bytes(src []u8) !ObjectIdentifier {
	// maybe two integer fits in 1 bytes
	if src.len == 0 {
		return error('ObjectIdentifier: bad string oid length')
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

	oid := ObjectIdentifier{
		value: s
	}
	if !oid.validate() {
		return error('ObjectIdentifier: failed to validate')
	}
	return oid
}

fn (oid ObjectIdentifier) pack_into_bytes() ![]u8 {
	if !oid.validate() {
		return error('ObjectIdentifier: failed to validate')
	}
	mut dst := []u8{}
	// the first two components (a.b) of ObjectIdentifier are encoded as 40*a+b
	encode_base128_int(mut dst, i64(oid.value[0] * 40 + oid.value[1]))
	for i := 2; i < oid.value.len; i++ {
		encode_base128_int(mut dst, i64(oid.value[i]))
	}
	return dst
}

pub fn ObjectIdentifier.parse(mut p Parser) !ObjectIdentifier {
	tag := p.read_tag()!
	if !tag.equal(default_oid_tag) {
		return error('Bad ObjectIdentifier tag')
	}
	length := p.read_length()!
	bytes := p.read_bytes(length)!

	res := ObjectIdentifier.from_bytes(bytes)!

	return res
}

pub fn ObjectIdentifier.decode(src []u8) !(ObjectIdentifier, i64) {
	return ObjectIdentifier.decode_with_rule(src, .der)!
}

fn ObjectIdentifier.decode_with_rule(bytes []u8, rule EncodingRule) !(ObjectIdentifier, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, rule)!
	if !tag.equal(default_oid_tag) {
		return error('Unexpected non-oid tag')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!
	content := if length == 0 {
		[]u8{}
	} else {
		if content_pos >= bytes.len || content_pos + length > bytes.len {
			return error('ObjectIdentifier: truncated payload bytes')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}

	oid := ObjectIdentifier.from_bytes(content)!
	next := content_pos + length

	return oid, next
}

pub fn (oid ObjectIdentifier) equal(oth ObjectIdentifier) bool {
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

fn (oid ObjectIdentifier) str() string {
	if oid.value.len == 0 {
		return 'nil'
	}
	mut s := []string{}
	for i in oid.value {
		s << i.str()
	}
	return s.join('.')
}

fn (oid ObjectIdentifier) validate() bool {
	if oid.value.len > max_oid_length {
		return false
	}
	if oid.value.len < 2 || oid.value[0] > 2 || (oid.value[0] < 2 && oid.value[1] >= 40) {
		return false
	}
	return true
}

fn (oid ObjectIdentifier) oid_length() int {
	mut n := base128_int_length(i64(oid.value[0] * 40 + oid.value[1]))
	for i := 2; i < oid.value.len; i++ {
		n += base128_int_length(i64(oid.value[i]))
	}
	return n
}

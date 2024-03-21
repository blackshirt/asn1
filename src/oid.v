// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// TODO: doing check for limiting oid array length.
const max_oid_length = 128

// ObjectIdentifier
pub struct Oid {
	value []int
	tag   Tag = new_tag(.universal, false, int(TagType.oid)) or { panic(err) }
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

pub fn Oid.from_bytes(src []u8) !Oid {
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

pub fn Oid.from_string(s string) !Oid {
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

pub fn (oid Oid) tag() Tag {
	return oid.tag
}

pub fn (oid Oid) value() []int {
	return oid.value
}

pub fn (oid Oid) payload(p Params) ![]u8 {
	return oid.pack()!
}

pub fn (oid Oid) length(p Params) int {
	bytes := oid.pack() or { panic(err) }
	return bytes.len
}

pub fn (oid Oid) packed_length(p Params) int {
	mut n := 0
	n += oid.tag().packed_length(p)

	src := oid.pack() or { panic(err) }
	len := Length.from_i64(src.len) or { panic(err) }
	n += len.packed_length(p)
	n += src.len

	return n
}

fn (oid Oid) pack() ![]u8 {
	if !oid.validate() {
		return error('Oid: failed to validate')
	}
	mut dst := []u8{}
	encode_base128_int(mut dst, i64(oid.value[0] * 40 + oid.value[1]))
	for i := 2; i < oid.value.len; i++ {
		encode_base128_int(mut dst, i64(oid.value[i]))
	}
	return dst
}

pub fn (oid Oid) pack_to_asn1(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Oid: unsupported mode')
	}
	// packing in DER mode
	bytes := oid.pack()!
	oid.tag().pack_to_asn1(mut dst, p)!
	length := Length.from_i64(bytes.len)!
	length.pack_to_asn1(mut dst, p)!
	dst << bytes
}

pub fn Oid.unpack_from_asn1(src []u8, loc i64, p Params) !(Oid, i64) {
	if src.len < 2 {
		return error('Oid: bad payload len')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Oid: unsupported mode')
	}
	if loc > src.len {
		return error('Oid: bad position offset')
	}
	// unpacking in DER mode
	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	if tag.class() != .universal || tag.is_constructed() || tag.tag_number() != int(TagType.oid) {
		return error('Oid: bad tag of universal class type')
	}
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// no bytes
	if len == 0 {
		ret := Oid{
			tag: tag
		}
		return ret, idx
	}
	if idx > src.len || idx + len > src.len {
		return error('Oid: truncated input')
	}
	// TODO: check the length, its safe to access bytes
	bytes := unsafe { src[idx..idx + len] }

	oid := Oid.from_bytes(bytes)!
	return oid, idx + len
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

pub fn (oid Oid) str() string {
	mut s := []string{}
	for i in oid.value {
		s << i.str()
	}
	return s.join('.')
}

fn (oid Oid) validate() bool {
	if oid.value.len > asn1.max_oid_length {
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

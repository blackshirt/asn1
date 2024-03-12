// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// TODO: doing check for limiting oid array length.
const max_oid_length = 128

// ObjectIdentifier
struct Oid {
	value []int
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.oid)) or { panic(err) }
}

fn Oid.from_ints(src []int) !Oid {
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

fn Oid.from_bytes(b []u8) !Oid {
	// maybe two integer fits in 1 bytes
	if b.len == 0 {
		return error('Oid: bad string oid length')
	}
	mut s := []int{len: b.len + 1}

	mut val, mut pos := asn1.decode_base128_int(b, 0)!

	if val < 80 {
		s[0] = val / 40
		s[1] = val % 40
	} else {
		s[0] = 2
		s[1] = val - 80
	}
	mut i := 2
	for ; pos < b.len; i++ {
		val, pos = asn1.decode_base128_int(b, pos)!
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

fn Oid.from_string(s string) !Oid {
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

fn (oid Oid) tag() asn1.Tag {
	return oid.tag
}

fn (oid Oid) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	match mode {
		.ber, .der {
			bytes := oid.pack()!
			oid.tag().pack_to_asn1(mut to, mode, p)!
			length := asn1.Length.from_i64(bytes.len)!
			length.pack_to_asn1(mut to, mode, p)!
			to << bytes
		}
		else {
			return error('Unsupported mode')
		}
	}
}

fn Oid.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(Oid, i64) {
	if b.len < 2 {
		return error('Oid: bad payload len')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.oid) {
				return error('Oid: bad tag of universal class type')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			if idx + len > b.len {
				return error('Oid: truncated input')
			}
			// TODO: check the length, its safe to access bytes
			bytes := unsafe { b[idx..idx + len] }

			oid := Oid.from_bytes(bytes)!
			return oid, idx + len
		}
		else {
			return error('Unsupported mode')
		}
	}
}

fn (oid Oid) pack() ![]u8 {
	if !oid.validate() {
		return error('Oid: failed to validate')
	}
	mut dst := []u8{}
	asn1.encode_base128_int(mut dst, i64(oid.value[0] * 40 + oid.value[1]))
	for i := 2; i < oid.value.len; i++ {
		asn1.encode_base128_int(mut dst, i64(oid.value[i]))
	}
	return dst
}

fn (oid Oid) equal(oth Oid) bool {
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
	mut s := []string{}
	for i in oid.value {
		s << i.str()
	}
	return s.join('.')
}

fn (oid Oid) validate() bool {
	if oid.value.len > primitive.max_oid_length {
		return false
	}
	if oid.value.len < 2 || oid.value[0] > 2 || (oid.value[0] < 2 && oid.value[1] >= 40) {
		return false
	}
	return true
}

fn (oid Oid) oid_length() int {
	mut n := asn1.base128_int_length(i64(oid.value[0] * 40 + oid.value[1]))
	for i := 2; i < oid.value.len; i++ {
		n += asn1.base128_int_length(i64(oid.value[i]))
	}
	return n
}

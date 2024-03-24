// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// IA5String handling routine
// Standard ASCII characters
pub struct IA5String {
	tag   Tag = Tag{.universal, false, int(TagType.ia5string)}
	value string
}

// from_string creates IA5String from string s
pub fn IA5String.from_string(s string) !IA5String {
	if !valid_ia5string(s) {
		return error('IA5String: contains non-ascii chars')
	}
	return IA5String{
		value: s
	}
}

// from_bytes creates a new IA5String from bytes b
pub fn IA5String.from_bytes(b []u8) !IA5String {
	if b.any(it < u8(` `) || it > u8(`~`)) {
		return error('IA5String: bytes contains non-ascii chars')
	}
	return IA5String{
		value: b.bytestr()
	}
}

pub fn (v IA5String) tag() Tag {
	return v.tag
}

pub fn (v IA5String) value() string {
	return v.value
}

pub fn (v IA5String) payload(p Params) ![]u8 {
	if !v.value.is_ascii() {
		return error('IA5String: contains non-ascii chars')
	}
	return v.value.bytes()
}

pub fn (v IA5String) length(p Params) int {
	return v.value.len
}

pub fn (v IA5String) packed_length(p Params) int {
	mut n := 0

	n += v.tag().packed_length(p)
	len := Length.from_i64(v.value.bytes().len) or { panic(err) }
	n += len.packed_length(p)
	n += v.value.bytes().len

	return n
}

pub fn (v IA5String) encode(mut dst []u8, p Params) ! {
	if !v.value.is_ascii() {
		return error('IA5String: contains non-ascii char')
	}
	if p.mode != .der && p.mode != .ber {
		return error('IA5String: unsupported mode')
	}

	v.tag().encode(mut dst, p)!
	bytes := v.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.encode(mut dst, p)!
	dst << bytes
}

pub fn IA5String.decode(src []u8, loc i64, p Params) !(IA5String, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	// TODO: checks tag for matching type
	if raw.tag.class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.ia5string) {
		return error('IA5String: bad tag of universal class type')
	}
	// no bytes
	if raw.length(p) == 0 {
		return IA5String{}, next
	}

	// check for ASCII charset
	if raw.payload.any(it < u8(` `) || it > u8(`~`)) {
		return error('IA5String: bytes contains non-ascii chars')
	}
	ret := IA5String{
		value: raw.payload.bytestr()
	}
	return ret, next
}

// Utility function
fn valid_ia5string(s string) bool {
	return s.is_ascii()
}

// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// VisibleString
// The ASN.1 VisibleString type supports a subset of ASCII characters that does not include control characters.
//
pub struct VisibleString {
	tag Tag = Tag{.universal, false, int(TagType.visiblestring)}
mut:
	value string
}

// from_string creates a new VisibleString from string s
pub fn VisibleString.from_string(s string, p Params) !VisibleString {
	if contains_ctrl_chars(s.bytes()) {
		return error('VisibleString: contains control chars')
	}
	return VisibleString{
		value: s
	}
}

// from_bytes creates a new VisibleString from bytes src
pub fn VisibleString.from_bytes(src []u8, p Params) !VisibleString {
	if contains_ctrl_chars(src) {
		return error('VisibleString: contains control chars')
	}
	return VisibleString{
		value: src.bytestr()
	}
}

pub fn (vs VisibleString) tag() Tag {
	return vs.tag
}

pub fn (vs VisibleString) value() string {
	return vs.value
}

pub fn (vs VisibleString) payload(p Params) ![]u8 {
	if contains_ctrl_chars(vs.value.bytes()) {
		return error('VisibleString: contains control chars')
	}
	return vs.value.bytes()
}

pub fn (vs VisibleString) length(p Params) int {
	return vs.value.len
}

pub fn (vs VisibleString) packed_length(p Params) int {
	mut n := 0
	n += vs.tag().packed_length(p)
	len := Length.from_i64(vs.length(p)) or { panic(err) }
	n += len.packed_length(p)
	n += vs.length(p)

	return n
}

pub fn (vs VisibleString) encode(mut dst []u8, p Params) ! {
	// recheck
	if contains_ctrl_chars(vs.value.bytes()) {
		return error('VisibleString: contains control chars')
	}
	if p.mode != .der && p.mode != .ber {
		return error('VisibleString: unsupported mode')
	}
	vs.tag().encode(mut dst, p)!
	length := Length.from_i64(vs.value.bytes().len)!
	length.encode(mut dst, p)!
	dst << vs.value.bytes()
}

pub fn VisibleString.decode(src []u8, loc i64, p Params) !(VisibleString, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.visiblestring) {
		return error('VisibleString: bad tag of universal class type')
	}

	// no bytes
	if raw.payload.len == 0 {
		return VisibleString{}, next
	}
	vs := VisibleString.from_bytes(raw.payload, p)!
	return vs, next
}

// Utility function
//
fn is_ctrl_char(c u8) bool {
	return (c >= 0 && c <= 0x1f) || c == 0x7f
}

fn contains_ctrl_chars(src []u8) bool {
	return src.any(is_ctrl_char(it))
}

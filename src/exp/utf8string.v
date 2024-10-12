// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import encoding.utf8

// Utf8String
// UTF8 unicode charset
//
@[heap; noinit]
pub struct Utf8String {
pub:
	value string
}

pub fn Utf8String.new(s string) !Utf8String {
	if !utf8.validate_str(s) {
		return error('Utf8String: invalid UTF-8 string')
	}
	return Utf8String{
		value: s
	}
}

pub fn Utf8String.from_bytes(src []u8) !Utf8String {
	if !utf8.validate_str(src.bytestr()) {
		return error('Utf8String: invalid UTF-8 string')
	}
	return UtfString{
		value: src.bytestr()
	}
}

pub fn (uts Utf8String) tag() Tag {
	return Tag{.universal, false, u32(TagType.utf8string)}
}

pub fn (uts Utf8String) payload(p Params) ![]u8 {
	return uts.payload_with_rule(.der)!
}

fn (uts Utf8String) str() string {
	if uts.value.len == 0 {
		return 'Utf8String: (<empty>)'
	}
	return 'Utf8String: (${uts.value})'
}

fn (uts Utf8String) payload_with_rule(rule EncodingRule) ![]u8 {
	if rule != .der && rule != .ber {
		return error('Utf8String: Unsupported rule')
	}
	if !utf8.validate_str(uts.value) {
		return error('Utf8String: invalid UTF-8 string')
	}
	return uts.value.bytes()
}

fn Utf8String.decode(src []u8, loc i64, p Params) !(Utf8String, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.tag_class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.utf8string) {
		return error('Utf8String: bad tag of universal class type')
	}
	// no bytes
	if raw.payload.len == 0 {
		return Utf8String{}, next
	}
	uts := Utf8String.from_bytes(raw.payload, p)!
	return uts, next
}

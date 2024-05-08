// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import encoding.utf8

// UTF8String
// UTF8 unicode charset
//
pub struct UTF8String {
	tag Tag = Tag{.universal, false, int(TagType.utf8string)}
mut:
	value string
}

pub fn UTF8String.from_string(s string, p Params) !UTF8String {
	if !utf8.validate_str(s) {
		return error('UTF8String: invalid UTF-8 string')
	}
	return UTF8String{
		value: s
	}
}

pub fn UTF8String.from_bytes(src []u8, p Params) !UTF8String {
	if !utf8.validate_str(src.bytestr()) {
		return error('UTF8String: invalid UTF-8 string')
	}
	return UTF8String{
		value: src.bytestr()
	}
}

pub fn (us UTF8String) tag() Tag {
	return us.tag
}

pub fn (us UTF8String) value() string {
	return us.value
}

pub fn (us UTF8String) payload(p Params) ![]u8 {
	if !utf8.validate_str(us.value) {
		return error('UTF8String: invalid UTF-8 string')
	}
	return us.value.bytes()
}

pub fn (us UTF8String) length(p Params) !int {
	return us.value.len
}

pub fn (us UTF8String) packed_length(p Params) !int {
	mut n := 0
	n += us.tag.packed_length(p)!
	uslen := us.length(p)!
	len := Length.from_i64(uslen)!
	n += len.packed_length(p)!
	n += uslen

	return n
}

pub fn (us UTF8String) encode(mut dst []u8, p Params) ! {
	// recheck
	if !utf8.validate_str(us.value) {
		return error('UTF8String: invalid UTF-8 string')
	}
	if p.mode != .der && p.mode != .ber {
		return error('UTF8String: unsupported mode')
	}
	us.tag.encode(mut dst, p)!
	length := Length.from_i64(us.value.bytes().len)!
	length.encode(mut dst, p)!
	dst << us.value.bytes()
}

pub fn UTF8String.decode(src []u8, loc i64, p Params) !(UTF8String, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.utf8string) {
		return error('UTF8String: bad tag of universal class type')
	}
	// no bytes
	if raw.payload.len == 0 {
		return UTF8String{}, next
	}
	uts := UTF8String.from_bytes(raw.payload, p)!
	return uts, next
}

// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import encoding.utf8

// UTF8String
// UTF8 unicode charset
//
pub struct UTF8String {
	value string
mut:
	tag Tag = new_tag(.universal, false, int(TagType.utf8string)) or { panic(err) }
}

pub fn UTF8String.from_string(s string) !UTF8String {
	if !utf8.validate_str(s) {
		return error('UTF8String: invalid UTF-8 string')
	}
	return UTF8String{
		value: s
	}
}

pub fn UTF8String.from_bytes(src []u8) !UTF8String {
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

pub fn (us UTF8String) payload(p Params) ![]u8 {
	if !utf8.validate_str(us.value) {
		return error('UTF8String: invalid UTF-8 string')
	}
	return us.value.bytes()
}

pun fn (us UTF8String) length(p Params) int {
	return us.value.len
}

pub fn (us UTF8String) packed_length(p Params) int {
	mut n := 0
	n += us.tag().packed_length(p)
	uslen := us.length(p)
	len := Length.from_i64(uslen) or { panic(err) }
	n += len.packed_length(p)
	n += uslen

	return n
}

pub fn (us UTF8String) pack_to_asn1(mut dst []u8, p Params) ! {
	// recheck
	if !utf8.validate_str(us.value) {
		return error('UTF8String: invalid UTF-8 string')
	}
	if p.mode != .der && p.mode != .ber {
		return error('UTF8String: unsupported mode')
	}
	us.tag().pack_to_asn1(mut dst, p)!
	length := Length.from_i64(us.value.bytes().len)!
	length.pack_to_asn1(mut dst, p)!
	dst << us.value.bytes()
}

pub fn UTF8String.unpack_from_asn1(src []u8, loc i64, p Params) !(UTF8String, i64) {
	if src.len < 2 {
		return error('UTF8String: src.len underflow')
	}
	if p.mode != .der && p.mode != .ber {
		return error('OctetString: unsupported mode')
	}
	if loc > src.len {
		return error('OctetString: bad position offset')
	}

	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	if tag.class() != .universal || tag.is_constructed()
		|| tag.tag_number() != int(TagType.utf8string) {
		return error('UTF8String: bad tag of universal class type')
	}
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// no bytes
	if len == 0 {
		ret := UTF8String{
			tag: tag
		}
		return ret, idx
	}
	if idx > src.len || idx + len > src.len {
		return error('UTF8String: truncated input')
	}
	bytes := unsafe { src[idx..idx + len] }

	us := UTF8String.from_bytes(bytes)!
	return us, idx + len
}

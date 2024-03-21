// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// NumericString.
//
// NumericString was restricted character string types
// restricted to sequences of zero, one or more characters from some
// specified collection of characters.
// That was : digit : 0,1,..9 and spaces char (0x20)
pub struct NumericString {
	value string
mut:
	tag Tag = new_tag(.universal, false, int(TagType.numericstring)) or { panic(err) }
}

// new_numeric_string creates new numeric string
pub fn NumericString.from_string(s string) !NumericString {
	if !all_numeric_string(s.bytes()) {
		return error('NumericString: contains non-numeric string')
	}
	return NumericString{
		value: s
	}
}

pub fn NumericString.from_bytes(bytes []u8) !NumericString {
	if !all_numeric_string(bytes) {
		return error('NumericString: contains non-numeric string')
	}
	return NumericString{
		value: bytes.bytestr()
	}
}

pub fn (ns NumericString) tag() Tag {
	return ns.tag
}

pub fn (ns NumericString) value() string {
	return ns.value
}

pub fn (ns NumericString) payload(p Params) ![]u8 {
	return ns.value.bytes()
}

pub fn (ns NumericString) length(p Params) int {
	return ns.value.len
}

pub fn (ns NumericString) packed_length(p Params) int {
	mut n := 0

	n += ns.tag().packed_length(p)
	len := Length.from_i64(ns.value.bytes().len) or { panic(err) }
	n += len.packed_length(p)
	n += ns.value.bytes().len

	return n
}

pub fn (ns NumericString) pack_to_asn1(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}

	ns.tag().pack_to_asn1(mut dst, p)!
	length := Length.from_i64(ns.value.bytes().len)!
	length.pack_to_asn1(mut dst, p)!
	dst << ns.value.bytes()
}

pub fn NumericString.unpack_from_asn1(src []u8, loc i64, p Params) !(NumericString, i64) {
	if src.len < 2 {
		return error('NumericString: src.len underflow')
	}
	if p.mode != .der && p.mode != .ber {
		return error('NumericString: unsupported mode')
	}
	if loc > src.len {
		return error('NumericString: bad position offset')
	}

	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	if tag.class() != .universal || tag.is_constructed()
		|| tag.tag_number() != int(TagType.numericstring) {
		return error('NumericString: bad tag of universal class type')
	}
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// no bytes
	if len == 0 {
		ret := NumericString{
			tag: tag
		}
		return ret, idx
	}
	if idx > src.len || idx + len > src.len {
		return error('NumericString: truncated input')
	}

	// TODO: check the length, its safe to access bytes
	bytes := unsafe { src[idx..idx + len] }

	ns := NumericString.from_bytes(bytes)!
	return ns, idx + len
}

// Utility function
//
fn all_numeric_string(bytes []u8) bool {
	return bytes.all(is_numericstring(it))
}

fn is_numericstring(c u8) bool {
	return c.is_digit() || c == u8(0x20)
}

// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// NumericString.
//
// NumericString was restricted character string types
// restricted to sequences of zero, one or more characters from some
// specified collection of characters.
// That was : digit : 0,1,..9 and spaces char (0x20)
struct NumericString {
	value string
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.numericstring)) or { panic(err) }
}

// new_numeric_string creates new numeric string
fn NumericString.from_string(s string) !NumericString {
	if !all_numeric_string(s.bytes()) {
		return error('NumericString: contains non-numeric string')
	}
	return NumericString{
		value: s
	}
}

fn NumericString.from_bytes(bytes []u8) !NumericString {
	if !all_numeric_string(bytes) {
		return error('NumericString: contains non-numeric string')
	}
	return NumericString{
		value: bytes.bytestr()
	}
}

fn (ns NumericString) tag() asn1.Tag {
	return ns.tag
}

fn (ns NumericString) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	match mode {
		.ber, .der {
			ns.tag().pack_to_asn1(mut to, mode, p)!
			length := asn1.Length.from_i64(ns.value.bytes().len)!
			length.pack_to_asn1(mut to, mode, p)!
			to << ns.value.bytes()
		}
		else {
			return error('unsupported')
		}
	}
}

fn NumericString.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(NumericString, i64) {
	if b.len < 2 {
		return error('NumericString: bad b.len underflow')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.numericstring) {
				return error('NumericString: bad tag of universal class type')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			// TODO: check the length, its safe to access bytes
			bytes := unsafe { b[idx..idx + len] }

			ns := NumericString.from_bytes(bytes)!
			return ns, idx + len
		}
		else {
			return error('Unsupported mode')
		}
	}
}

// Utility function
fn all_numeric_string(bytes []u8) bool {
	return bytes.all(is_numericstring(it))
}

fn is_numericstring(c u8) bool {
	return c.is_digit() || c == u8(0x20)
}

/*
pub fn (ns NumericString) length() int {
	return ns.len
}

pub fn (ns NumericString) size() int {
	mut size := 0
	tag := ns.tag()
	taglen := calc_tag_length(tag)
	size += taglen

	lol := calc_length_of_length(ns.length())
	size += int(lol)

	size += ns.length()

	return size
}

pub fn (ns NumericString) encode() ![]u8 {
	out := serialize_numericstring(ns)!
	return out
}

fn serialize_numericstring(s string) ![]u8 {
	p := s.bytes()
	// check for numeric string
	for c in p {
		if !is_numericstring(c) {
			return error('invalid_char_error')
		}
	}

	mut dst := []u8{}
	t := new_tag(.universal, false, int(TagType.numericstring))

	serialize_tag(mut dst, t)
	serialize_length(mut dst, p.len)

	dst << p

	return dst
}

fn decode_numericstring(payload []u8) !(Tag, string) {
	// minimum header payload
	if payload.len < 2 {
		return error('decode numeric: bad payload len')
	}

	tag, pos := read_tag(payload, 0)!
	if tag.number != int(TagType.numericstring) {
		return error('bad tag')
	}
	if pos > payload.len {
		return error('truncated input')
	}

	// mut length := 0
	length, next := decode_length(payload, pos)!

	if next > payload.len {
		return error('truncated input')
	}

	// remaining data, ony slicing required part
	out := read_bytes(payload, next, length)!
	// check for valid numeric value
	for c in out {
		if !is_numericstring(c) {
			return error('invalid char_error')
		}
	}
	return tag, out.bytestr()
}
*/

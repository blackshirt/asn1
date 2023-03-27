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
type NumericString = string

// new_numeric_string creates new numeric string
pub fn new_numeric_string(s string) !Encoder {
	for c in s.bytes() {
		if !is_numericstring(c) {
			return error('invalid char')
		}
	}
	return NumericString(s)
}

pub fn (ns NumericString) tag() Tag {
	return new_tag(.universal, false, int(TagType.numericstring))
}

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

fn is_numericstring(c u8) bool {
	return c.is_digit() || c == u8(0x20)
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

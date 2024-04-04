// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// GeneralString handling routine
// Standard ASCII characters
// TODO: NEED TO BE FIXED, NOT TESTED
type GeneralString = string

pub fn new_generalstring(s string) !GeneralString {
	if !is_generalstring(s) {
		return error('bad ascii string')
	}
	return GeneralString(s)
}

pub fn (gn GeneralString) tag() Tag {
	return new_tag(.universal, false, int(TagType.generalstring))
}

pub fn (gn GeneralString) length() int {
	return gn.len
}

pub fn (gn GeneralString) size() int {
	mut size := 0
	tag := gn.tag()
	t := calc_tag_length(tag)
	size += t

	lol := calc_length_of_length(gn.length())
	size += int(lol)

	size += gn.length()

	return size
}

pub fn (gn GeneralString) encode() ![]u8 {
	return serialize_generalstring(gn)
}

pub fn GeneralString.decode(src []u8) !GeneralString {
	_, val := decode_generalstring(src)!
	return GeneralString(val)
}

fn (gn GeneralString) str() string {
	return 'generalstring ${string(gn)}'
}

fn is_generalstring(c string) bool {
	return c.is_ascii()
}

fn serialize_generalstring(s string) ![]u8 {
	if !is_generalstring(s) {
		return error('contains invalid char')
	}

	t := new_tag(.universal, false, int(TagType.generalstring))
	mut out := []u8{}

	serialize_tag(mut out, t)
	p := s.bytes()
	serialize_length(mut out, p.len)
	out << p
	return out
}

fn decode_generalstring(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode numeric: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.generalstring) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	// mut length := 0
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!

	if !is_generalstring(out.bytestr()) {
		return error('contains invalid char')
	}
	return tag, out.bytestr()
}

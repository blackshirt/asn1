// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// OCTETSTRING
//
// octetstring handling
type OctetString = string

// new_octetstring creates new octet string
pub fn new_octetstring(s string) Encoder {
	return OctetString(s)
}

pub fn (os OctetString) tag() Tag {
	return new_tag(.universal, false, int(TagType.octetstring))
}

pub fn (os OctetString) length() int {
	return os.len
}

pub fn (os OctetString) size() int {
	mut size := 0
	tag := os.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(os.length())
	size += int(l)

	size += os.length()

	return size
}

pub fn (os OctetString) encode() ![]u8 {
	return serialize_octetstring(os)
}

fn serialize_octetstring(s string) ![]u8 {
	tag := new_tag(.universal, false, int(TagType.octetstring))
	mut out := []u8{}

	serialize_tag(mut out, tag)

	bs := s.bytes()
	serialize_length(mut out, bs.len)
	out << bs

	return out
}

fn decode_octetstring(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.octetstring) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!
	val := out.bytestr()

	return tag, val
}

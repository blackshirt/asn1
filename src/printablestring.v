// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// PrintableString
//
// PrintableString consists of:
// Latin capital letters A, B, ... Z
// Latin small letters a, b, ... z
// Digits 0, 1, ... 9
// symbols:  (space) ' ( ) + , - . / : = ?
//
const printable_symbols = r"(')+,-./:=?".bytes()

type PrintableString = string

// new_printable_string creates PrintableString from the string s
pub fn new_printable_string(s string) !Encoder {
	for c in s.bytes() {
		if !is_printablestring(c) {
			return error('invalid printable char')
		}
	}
	return PrintableString(s)
}

pub fn (ps PrintableString) tag() Tag {
	return new_tag(.universal, false, int(TagType.printablestring))
}

pub fn (ps PrintableString) length() int {
	return ps.len
}

pub fn (ps PrintableString) size() int {
	mut size := 0
	tag := ps.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(ps.length())
	size += int(l)

	size += ps.length()

	return size
}

pub fn (ps PrintableString) encode() ![]u8 {
	return serialize_printablestring(ps)
}

pub fn PrintableString.decode(src []u8) !PrintableString {
	_, v := decode_printablestring(src)!

	return PrintableString(v)
}

fn (ps PrintableString) str() string {
	return 'PRINTABLESTRING ${string(ps)}'
}

fn is_printablestring(c u8) bool {
	return c.is_alnum() || c == u8(0x20) || c in asn1.printable_symbols
}

fn decode_printablestring(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode numeric: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.printablestring) {
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

	// remaining data, ony slicing required parts
	out := read_bytes(src, next, length)!
	for c in out {
		if !is_printablestring(c) {
			return error('invalid char error')
		}
	}
	return tag, out.bytestr()
}

fn serialize_printablestring(s string) ![]u8 {
	p := s.bytes()
	for c in s {
		if !is_printablestring(c) {
			return error('invalid char error')
		}
	}

	t := new_tag(.universal, false, int(TagType.printablestring))
	mut out := []u8{}

	serialize_tag(mut out, t)
	serialize_length(mut out, p.len)
	out << p
	return out
}

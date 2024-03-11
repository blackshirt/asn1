// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// PrintableString
//
// PrintableString consists of:
// Latin capital letters A, B, ... Z
// Latin small letters a, b, ... z
// Digits 0, 1, ... 9
// symbols:  (space) ' ( ) + , - . / : = ?
//
const printable_symbols = r"(')+,-./:=?".bytes()

struct PrintableString {
	value string
mut:
	tag asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.printablestring))!
}

fn PrintableString.from_string(s string) !PrintableString {
	if !printable_chars(s.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	return PrintableString{
		value: s
	}
}

fn PrintableString.from_bytes(b []u8) !PrintableString {
	if !printable_chars(b) {
		return error('PrintableString: contains non-printable string')
	}
	return PrintableString{
		value: b.bytestr()
	}
}

fn (ps PrintableString) tag() asn1.Tag {
	return ps.tag
}

fn (ps PrintableString) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	// recheck
	if !printable_chars(ps.value.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	match mode {
		.ber, .der {
			ps.tag().pack_to_asn1(mut to, mode, p)!
			length := asn1.Length.from_i64(ps.value.bytes().len)!
			length.pack_to_asn1(mut to, mode, p)!
			to << ps.value.bytes()
		}
		else {
			return error('unsupported')
		}
	}
}

fn PrintableString.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(PrintableString, i64) {
	if b.len < 2 {
		return error('PrintableString: bad b.len underflow')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.printablestring) {
				return error('PrintableString: bad tag of universal class type')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			// TODO: check the length, its safe to access bytes
			bytes := unsafe { b[idx..idx + len] }

			ps := PrintableString.from_bytes(bytes)!
			return ps, idx + len
		}
		else {
			return error('Unsupported mode')
		}
	}
}

// utility function
fn printable_chars(bytes []u8) bool {
	return bytes.all(is_printablestring(it))
}

fn is_printablestring(c u8) bool {
	return c.is_alnum() || c == u8(0x20) || c in primitive.printable_symbols
}

/*
// new_printable_string creates PrintableString from the string s
pub fn new_printable_string(s string) !Encoder {
	for c in s.bytes() {
		if !is_printablestring(c) {
			return error('invalid printable char')
		}
	}
	return PrintableString(s)
}

fn (ps PrintableString) tag() asn1.Tag {
	return ps.tag
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

fn (ps PrintableString) str() string {
	return 'PRINTABLESTRING ${string(ps)}'
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
*/

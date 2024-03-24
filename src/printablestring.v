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

pub struct PrintableString {
	value string
	tag   Tag = Tag{.universal, false, int(TagType.printablestring)}
}

pub fn PrintableString.from_string(s string) !PrintableString {
	if !printable_chars(s.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	return PrintableString{
		value: s
	}
}

pub fn PrintableString.from_bytes(src []u8) !PrintableString {
	if !printable_chars(src) {
		return error('PrintableString: contains non-printable string')
	}
	return PrintableString{
		value: src.bytestr()
	}
}

pub fn (ps PrintableString) tag() Tag {
	return ps.tag
}

pub fn (ps PrintableString) value() string {
	return ps.value
}

pub fn (ps PrintableString) payload(p Params) ![]u8 {
	if !printable_chars(ps.value.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	return ps.value.bytes()
}

pub fn (ps PrintableString) length(p Params) int {
	return ps.value.len
}

pub fn (ps PrintableString) packed_length(p Params) int {
	mut n := 0
	n += ps.tag().packed_length(p)
	len := ps.length(p)
	pslen := Length.from_i64(len) or { panic(err) }
	n += pslen.packed_length(p)
	n += len

	return n
}

pub fn (ps PrintableString) encode(mut dst []u8, p Params) ! {
	// recheck
	if !printable_chars(ps.value.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	if p.mode != .der && p.mode != .ber {
		return error('PrintableString: unsupported mode')
	}
	// pack in DER mode
	ps.tag().encode(mut dst, p)!
	length := Length.from_i64(ps.value.bytes().len)!
	length.encode(mut dst, p)!
	dst << ps.value.bytes()
}

pub fn PrintableString.decode(src []u8, loc i64, p Params) !(PrintableString, i64) {
	raw, next := RawElement.decode(src, loc, p)!

	if raw.tag.class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.printablestring) {
		return error('PrintableString: bad tag of universal class type')
	}
	if raw.length(p) == 0 {
		return PrintableString{}, next
	}
	ps := PrintableString.from_bytes(raw.payload)!
	return ps, next
}

// utility function
fn printable_chars(bytes []u8) bool {
	return bytes.all(is_printablestring(it))
}

fn is_printablestring(c u8) bool {
	return c.is_alnum() || c == u8(0x20) || c in asn1.printable_symbols
}

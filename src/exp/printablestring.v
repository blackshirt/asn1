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

@[heap; noinit]
pub struct PrintableString {
pub:
	value string
}

fn (pst PrintableString) str() string {
	if pst.value.len == 0 {
		return 'PrintableString (<empty>)'
	}
	return 'PrintableString (${pst.value})'
}

pub fn (pst PrintableString) tag() Tag {
	return Tag{.universal, false, u32(TagType.printablestring)}
}

pub fn PrintableString.new(s string) !PrintableString {
	return PrintableString.from_bytes(s.bytes())!
}

fn PrintableString.from_bytes(src []u8) !PrintableString {
	if !printable_chars(src) {
		return error('PrintableString: contains non-printable string')
	}
	return PrintableString{
		value: src.bytestr()
	}
}

pub fn (pst PrintableString) payload() ![]u8 {
	if !printable_chars(pst.value.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	return pst.value.bytes()
}

pub fn PrintableString.decode(src []u8, loc i64, p Params) !(PrintableString, i64) {
	raw, next := RawElement.decode(src, loc, p)!

	if raw.tag.tag_class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.printablestring) {
		return error('PrintableString: bad tag of universal class type')
	}
	if raw.payload.len == 0 {
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
	return c.is_alnum() || c == u8(0x20) || c in printable_symbols
}

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

struct PrintableString {
	value string
mut:
	tag Tag = new_tag(.universal, false, int(TagType.printablestring)) or { panic(err) }
}

fn PrintableString.from_string(s string) !PrintableString {
	if !printable_chars(s.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	return PrintableString{
		value: s
	}
}

fn PrintableString.from_bytes(src []u8) !PrintableString {
	if !printable_chars(src) {
		return error('PrintableString: contains non-printable string')
	}
	return PrintableString{
		value: src.bytestr()
	}
}

fn (ps PrintableString) tag() Tag {
	return ps.tag
}

fn (ps PrintableString) payload(p Params) ![]u8 {
	if !printable_chars(ps.value.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	return ps.value.bytes()
}

fn (ps PrintableString) payload_length(p Params) int {
	return ps.value.len
}

fn (ps PrintableString) packed_length(p Params) int {
	mut n := 0
	n += ps.tag().packed_length(p)
	len := ps.payload_length(p)
	pslen := Length.from_i64(len) or { panic(err) }
	n += pslen.packed_length(p)
	n += len

	return n
}

fn (ps PrintableString) pack_to_asn1(mut dst []u8, p Params) ! {
	// recheck
	if !printable_chars(ps.value.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	if p.mode != .der && p.mode != .ber {
		return error('PrintableString: unsupported mode')
	}
	// pack in DER mode
	ps.tag().pack_to_asn1(mut dst, p)!
	length := Length.from_i64(ps.value.bytes().len)!
	length.pack_to_asn1(mut dst, p)!
	dst << ps.value.bytes()
}

fn PrintableString.unpack_from_asn1(src []u8, loc i64, p Params) !(PrintableString, i64) {
	if src.len < 2 {
		return error('PrintableString: bad src.len underflow')
	}
	if p.mode != .der && p.mode != .ber {
		return error('OctetString: unsupported mode')
	}
	if loc > src.len {
		return error('OctetString: bad position offset')
	}

	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	if tag.class() != .universal || tag.is_constructed()
		|| tag.tag_number() != int(TagType.printablestring) {
		return error('PrintableString: bad tag of universal class type')
	}
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	if len == 0 {
		ret := PrintableString{
			tag: tag
		}
		return ret, idx
	}
	if idx > src.len || idx + len > src.len {
		return error('PrintableString: truncated input')
	}
	// TODO: check the length, its safe to access bytes
	bytes := unsafe { src[idx..idx + len] }

	ps := PrintableString.from_bytes(bytes)!
	return ps, idx + len
}

// utility function
fn printable_chars(bytes []u8) bool {
	return bytes.all(is_printablestring(it))
}

fn is_printablestring(c u8) bool {
	return c.is_alnum() || c == u8(0x20) || c in asn1.printable_symbols
}

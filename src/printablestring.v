// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

const printable_symbols = r"(')+,-./:=?".bytes()
// The default tag of ASN.1 PRINTABLESTRING type.
const default_printablestring_tag = Tag{.universal, false, int(TagType.printablestring)}

// ASN.1 PRINTABLESTRING TYPE.
//
// PrintableString consists of:
// Latin capital letters A, B, ... Z
// Latin small letters a, b, ... z
// Digits 0, 1, ... 9
// symbols:  (space) ' ( ) + , - . / : = ?
//
@[noinit]
pub struct PrintableString {
pub:
	value string
}

pub fn PrintableString.new(s string) !PrintableString {
	return PrintableString.from_bytes(s.bytes())!
}

fn (pst PrintableString) str() string {
	if pst.value.len == 0 {
		return 'PrintableString (<empty>)'
	}
	return 'PrintableString (${pst.value})'
}

pub fn (pst PrintableString) tag() Tag {
	return default_printablestring_tag
}

pub fn (pst PrintableString) payload() ![]u8 {
	if !printable_chars(pst.value.bytes()) {
		return error('PrintableString: contains non-printable string')
	}
	return pst.value.bytes()
}

fn PrintableString.from_bytes(src []u8) !PrintableString {
	if !printable_chars(src) {
		return error('PrintableString: contains non-printable string')
	}
	return PrintableString{
		value: src.bytestr()
	}
}

// parse an PrintableString from on going Parser
pub fn PrintableString.parse(mut p Parser) !PrintableString {
	tag := p.read_tag()!
	if !tag.equal(default_printablestring_tag) {
		return error('Unexpected non-printablestring tag')
	}
	length := p.read_length()!
	content := p.read_bytes(length)!

	payload := if length == 0 { []u8{} } else { content }

	pst := PrintableString.from_bytes(payload)!
	return pst
}

pub fn PrintableString.decode(src []u8) !(PrintableString, i64) {
	return PrintableString.decode_with_rule(src, .der)!
}

fn PrintableString.decode_with_rule(bytes []u8, rule EncodingRule) !(PrintableString, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, rule)!
	if !tag.equal(default_printablestring_tag) {
		return error('Unexpected non-printablestring tag')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!
	content := if length == 0 {
		[]u8{}
	} else {
		if content_pos >= bytes.len || content_pos + length > bytes.len {
			return error('PrintableString: truncated payload bytes')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}

	pst := PrintableString.from_bytes(content)!
	next := content_pos + length

	return pst, next
}

// utility function
fn printable_chars(bytes []u8) bool {
	return bytes.all(is_printablestring(it))
}

fn is_printablestring(c u8) bool {
	return c.is_alnum() || c == u8(0x20) || c in printable_symbols
}

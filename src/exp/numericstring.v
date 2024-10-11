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
@[heap; noinit]
pub struct NumericString {
pub:
	value string
}

pub fn NumericString.parse(mut p Parser) !NumericString {
	tag := p.read_tag()!
	if !tag.expect(.universal, false, u32(TagType.numericstring)) {
		return error('Bad NumericString tag')
	}
	length := p.read_length()!
	bytes := p.read_bytes(length)!

	res := NumericString.from_bytes(bytes)!

	return res
}

// new_numeric_string creates new numeric string
pub fn NumericString.new(s string) !NumericString {
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

pub fn (ns NumericString) tag() Tag {
	return Tag{.universal, false, u32(TagType.numericstring)}
}

pub fn (ns NumericString) payload() ![]u8 {
	return ns.value.bytes()
}

fn NumericString.decode(bytes []u8) !(NumericString, i64) {
	ns, next := NumericString.decode_with_rule(bytes, .der)!
	return ns, next
}

fn NumericString.decode_with_rule(bytes []u8, rule EncodingRule) !(NumericString, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, rule)!
	if !tag.expect(.universal, false, u32(TagType.numericstring)) {
		return error('Unexpected non-numericstring tag')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!
	content := if length == 0 || content_pos == bytes.len {
		[]u8{}
	} else {
		if content_pos + length > bytes.len {
			return error('NumericString: truncated payload bytes')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}

	ns := NumericString.from_bytes(content)!
	next := content_pos + length

	return ns, next
}

// Utility function
//
fn all_numeric_string(bytes []u8) bool {
	return bytes.all(is_numericstring(it))
}

fn is_numericstring(c u8) bool {
	return c.is_digit() || c == u8(0x20)
}

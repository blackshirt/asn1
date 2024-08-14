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
pub struct NumericString {
	value string
mut:
	tag Tag = Tag{.universal, false, int(TagType.numericstring)}
}

// new_numeric_string creates new numeric string
pub fn NumericString.from_string(s string, p Params) !NumericString {
	if !all_numeric_string(s.bytes(), p) {
		return error('NumericString: contains non-numeric string')
	}
	return NumericString{
		value: s
	}
}

// NumericString.from_raw_element transforms RawElement in `re` into NumericString
pub fn NumericString.from_raw_element(re RawElement, p Params) !NumericString {
	// check validity of the RawElement tag
	if re.tag.tag_class() != .universal {
		return error('RawElement class is not .universal, but : ${re.tag.tag_class()}')
	}
	if p.mode == .der {
		if re.tag.is_constructed() {
			return error('RawElement constructed is not allowed in .der')
		}
	}
	if re.tag.number.universal_tag_type()! != .numericstring {
		return error('RawElement tag does not hold .numericstring type')
	}
	bytes := re.payload(p)!
	ns := NumericString.from_bytes(bytes, p)!

	return ns
}

pub fn NumericString.from_bytes(bytes []u8, p Params) !NumericString {
	if !all_numeric_string(bytes, p) {
		return error('NumericString: contains non-numeric string')
	}
	return NumericString{
		value: bytes.bytestr()
	}
}

pub fn (ns NumericString) tag() Tag {
	return ns.tag
}

pub fn (ns NumericString) value() string {
	return ns.value
}

pub fn (ns NumericString) payload(p Params) ![]u8 {
	return ns.value.bytes()
}

pub fn (ns NumericString) length(p Params) !int {
	return ns.value.len
}

pub fn (ns NumericString) packed_length(p Params) !int {
	mut n := 0

	n += ns.tag.packed_length(p)!
	len := Length.from_i64(ns.value.bytes().len)!
	n += len.packed_length(p)!
	n += ns.value.bytes().len

	return n
}

pub fn (ns NumericString) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}

	ns.tag.encode(mut dst, p)!
	length := Length.from_i64(ns.value.bytes().len)!
	length.encode(mut dst, p)!
	dst << ns.value.bytes()
}

pub fn NumericString.decode(src []u8, loc i64, p Params) !(NumericString, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	// correct way to check if this NumericString is in constucted form
	if raw.tag.tag_class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.numericstring) {
		return error('NumericString: bad tag of universal class type')
	}

	// no bytes
	if raw.payload.len == 0 {
		return NumericString{}, next
	}
	ns := NumericString.from_bytes(raw.payload)!
	return ns, next
}

// Utility function
//
fn all_numeric_string(bytes []u8, p Params) bool {
	return bytes.all(is_numericstring(it))
}

fn is_numericstring(c u8) bool {
	return c.is_digit() || c == u8(0x20)
}

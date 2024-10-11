// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 BOOLEAN
//
// A Boolean value can take true or false.
// ASN.1 DER encoding restricts encoding of boolean true value into 0xff
// and otherwise, encodes into zero (0x00) for false value.
// The encoding of a boolean value shall be primitive. The contents octets shall consist of a single octet.

@[noinit]
pub struct Boolean {
mut:
	// boolean value represented in single  byte to allow stores multiple value represents
	// true value others than 0xff, ie., non-null byte representing true value.
	value u8
}

pub fn (v Boolean) tag() Tag {
	return Tag{.universal, false, u32(TagType.boolean)}
}

fn (v Boolean) str() string {
	value := v.value()
	match value {
		false {
			return 'false'
		}
		true {
			return 'true'
		}
	}
}

// new creates a new Boolean value from true or false value
// By default, when you pass true, its would store 0xff as underlying byte value
// if you want more to be relaxed, see from_u8 to creates with another byte value
pub fn Boolean.new(value bool) Boolean {
	mut ret := Boolean{}
	val := if value { u8(0xff) } else { u8(0x00) }
	ret.value = val

	return ret
}

// from_u8 creates a new Boolean value from single byte value
pub fn Boolean.from_u8(value u8) Boolean {
	return Boolean{
		value: value
	}
}

fn parse_boolean(mut p Parser) !Boolean {
	return Boolean.parse(mut p)!
}

pub fn Boolean.parse(mut p Parser) !Boolean {
	value, next := Boolean.decode(p.data)!
	rest := if next > p.data.len { []u8{} } else { unsafe { p.data[next..] } }
	p.data = rest
	return value
}

// from_bytes creates a new ASN.1 BOOLEAN type from bytes b.
// Boolean type should fit in one byte length, otherwise it would return error.
// by default, p.rule == .der to follow DER restriction
fn Boolean.from_bytes(bytes []u8) !Boolean {
	return Boolean.from_bytes_with_rule(bytes, .der)
}

fn Boolean.from_bytes_with_rule(bytes []u8, rule EncodingRule) !Boolean {
	if bytes.len != 1 {
		return error('Boolean: bad bytes')
	}
	// for DER requirements that "If the encoding represents the boolean value TRUE,
	// its single contents octet shall have all eight bits set to one."
	// Thus only 0 and 255 are valid encoded values.
	// But, we relaxed this requirement to allow other than non-null
	// value to be treated as TRUE value, like in BER encoding.
	match bytes[0] {
		u8(0x00) {
			return Boolean.from_u8(0x00)
		}
		u8(0xff) {
			return Boolean.from_u8(0xff)
		}
		else {
			// other non-null value is treated as TRUE boolean value
			if rule == .der {
				return error('Boolean: in DER, other than 0xff is not allowed for true value')
			}
			return Boolean.from_u8(bytes[0])
		}
	}
}

pub fn (b Boolean) payload() ![]u8 {
	return b.payload_with_rule(.der)!
}

fn (b Boolean) payload_with_rule(rule EncodingRule) ![]u8 {
	// by default, true value is encoded to 0xff
	if rule == .der {
		if b.value != u8(0xff) && b.value != u8(0x00) {
			return error('Boolean: in .der, only 0xff or 0x00 are allowed')
		}
	}
	return [b.value]
}

// value gets the boolean value represented by underlying byte value
// It returnz FALSE ob the byte == 0x00 and TRUE otherwise.
pub fn (b Boolean) value() bool {
	return b.value_with_rule(.der)
}

fn (b Boolean) value_with_rule(rule EncodingRule) bool {
	match b.value {
		u8(0xff) {
			return true
		}
		u8(0x00) {
			return false
		}
		else {
			if rule == .der {
				return false
			}
			// otherwise non-null is considered as true
			return true
		}
	}
}

pub fn Boolean.decode(src []u8) !(Boolean, i64) {
	return Boolean.decode_with_rule(src, 0, .der)!
}

fn Boolean.decode_with_rule(src []u8, loc i64, rule EncodingRule) !(Boolean, i64) {
	if src.len < 3 {
		return error('Boolean: bad length bytes')
	}
	if rule != .der && rule != .ber {
		return error('Boolean: not supported rule')
	}
	tag, length_pos := Tag.decode_with_rule(src, loc, rule)!
	if !tag.expect(.universal, false, u32(TagType.boolean)) {
		return error('Unexpected non-boolean tag')
	}
	length, content_pos := Length.decode_with_rule(src, length_pos, rule)!
	if length != 1 {
		return error('Boolean: should have length 1')
	}
	if content_pos >= src.len || content_pos + length > src.len {
		return error('Boolean: truncated payload bytes')
	}
	payload := unsafe { src[content_pos..content_pos + length] }

	// boolean value should be encoded in single byte
	res := Boolean.from_bytes_with_rule(payload, rule)!
	next := content_pos + length
	return res, next
}

/*
// Boolean.from_raw_element transforms RawElement in `re` into Boolean
pub fn Boolean.from_raw_element(re RawElement, p Params) !Boolean {
	// check validity of the RawElement tag
	if re.tag.tag_class() != .universal {
		return error('RawElement class is not .universal, but get ${re.tag.tag_class()}')
	}
	if p.rule == .der {
		if re.tag.is_constructed() {
			return error('RawElement constructed is not allowed in .der')
		}
	}
	if re.tag.number.universal_tag_type()! != .boolean {
		return error('RawElement tag does not hold .boolean type')
	}
	bytes := re.payload(p)!
	bs := Boolean.from_bytes(bytes, p)!

	return bs
}
*/

/*
fn (v Boolean) length(p Params) !int {
	return 1
}

fn (v Boolean) packed_length(p Params) !int {
	mut n := 0
	n += v.tag.packed_length(p)!
	// boolean length should 1
	n += 1
	n += 1

	return n
}

pub fn (v Boolean) encode(mut dst []u8, p Params) ! {
	if p.rule != .der && p.rule != .ber {
		return error('Boolean: unsupported rule')
	}

	// in DER, true or false value packed into single byte of 0xff or 0x00 respectively
	v.tag.encode(mut dst, p)!
	length := Length.from_i64(1)!
	length.encode(mut dst, p)!
	// when rule != .der payload may contains not 0xff bytes
	payload := v.payload()!

	dst << payload
}


 */

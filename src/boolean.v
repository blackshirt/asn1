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

pub struct Boolean {
mut:
	tag Tag = Tag{.universal, false, int(TagType.boolean)}
	// boolean value represented in byte to allow stores multiple value represents
	// true value others than 0xff, ie., non-null byte representing true value.
	value u8
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

// value gets the boolean value represented by underlying byte value
// It returnz FALSE ob the byte == 0x00 and TRUE otherwise.
pub fn (b Boolean) value() bool {
	ret := if b.value == 0x00 { false } else { true }
	return ret
}

// from_bytes creates a new ASN.1 BOOLEAN type from bytes b.
// Boolean type should fit in one byte length, otherwise it would return error.
// by default, p.mode == .der to follow DER restriction
pub fn Boolean.from_bytes(b []u8, p Params) !Boolean {
	if b.len != 1 {
		return error('Boolean: bad bytes')
	}
	// for DER requirements that "If the encoding represents the boolean value TRUE,
	// its single contents octet shall have all eight bits set to one."
	// Thus only 0 and 255 are valid encoded values.
	// But, we relaxed this requirement to allow other than non-null
	// value to be treated as TRUE value, like in BER encoding.
	match b[0] {
		u8(0x00) {
			return Boolean.from_u8(0x00)
		}
		u8(0xff) {
			return Boolean.from_u8(0xff)
		}
		else {
			// other non-null value is treated as TRUE boolean value
			if p.mode == .der {
				return error('Boolean: in DER, other than 0xff is not allowed for true value')
			}
			return Boolean.from_u8(b[0])
		}
	}
}

pub fn (v Boolean) tag() Tag {
	return v.tag
}

pub fn (v Boolean) length(p Params) !int {
	return 1
}

pub fn (v Boolean) payload(p Params) ![]u8 {
	// by default, true value is encoded to 0xff
	if p.mode == .der {
		if v.value != u8(0xff) && v.value != u8(0x00) {
			return error('Boolean: in .der, only 0xff or 0x00 are allowed')
		}
	}
	return [v.value]
}

pub fn (v Boolean) packed_length(p Params) !int {
	mut n := 0
	n += v.tag.packed_length(p)!
	// boolean length should 1
	n += 1
	n += 1

	return n
}

pub fn (v Boolean) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Boolean: unsupported mode')
	}

	// in DER, true or false value packed into single byte of 0xff or 0x00 respectively
	v.tag.encode(mut dst, p)!
	length := Length.from_i64(1)!
	length.encode(mut dst, p)!
	// when mode != .der payload may contains not 0xff bytes
	payload := v.payload()!

	dst << payload
}

pub fn Boolean.decode(src []u8, loc i64, p Params) !(Boolean, i64) {
	if src.len < 3 {
		return error('Boolean: bad length bytes')
	}
	raw, next := RawElement.decode(src, loc, p)!

	if raw.tag.tag_class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.boolean) {
		return error('Boolean: bad tag of universal class type')
	}
	// boolean value should be encoded in single byte
	res := Boolean.from_bytes(raw.payload, p)!

	return res, next
}

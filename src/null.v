// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 NULL TYPE
pub struct Null {
	tag Tag = Tag{.universal, false, int(TagType.null)}
}

pub fn Null.new() Null {
	return Null{}
}

pub fn Null.from_raw_element(re RawElement, p Params) !Null {
	if re.payload(p)!.len != 0 {
		return error('Non-null RawElement payload')
	}
	// check validity of the RawElement tag
	if re.tag.tag_class() != .universal {
		return error('RawElement class is not .universal, but : ${re.tag.tag_class()}')
	}
	if p.mode == .der {
		if re.tag.is_constructed() {
			return error('RawElement constructed is not allowed in .der')
		}
	}
	if re.tag.number.universal_tag_type()! != .null {
		return error('RawElement tag does not hold .null type')
	}
	bytes := re.payload(p)!
	bs := Null.from_bytes(bytes, p)!

	return bs
}

pub fn Null.from_bytes(b []u8, p Params) !Null {
	if b.len != 0 {
		return error('Null: bad non-null bytes')
	}
	return Null{}
}

pub fn (n Null) tag() Tag {
	return n.tag
}

pub fn (n Null) length(p Params) !int {
	return 0
}

pub fn (n Null) payload(p Params) ![]u8 {
	return []u8{}
}

pub fn (n Null) packed_length(p Params) !int {
	return 2
}

pub fn (n Null) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}

	n.tag.encode(mut dst, p)!
	// the length is 0
	dst << [u8(0x00)]
}

fn Null.decode(src []u8, loc i64, p Params) !(Null, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.tag_class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.null) {
		return error('Null: bad tag=${raw.tag}')
	}
	if raw.length(p)! != 0 {
		return error('Null: len != 0')
	}
	ret := Null.from_bytes(raw.payload, p)!
	return ret, next
}

pub fn (n Null) str() string {
	return 'NULL'
}

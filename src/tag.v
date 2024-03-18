// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 tag handling routines.
// Its currently supports short form and long form for tag number bigger than 0x1f

// Standard universal tag number. some of them was
// deprecated, so its not going to be supported in this module.
pub enum TagType {
	reserved        = 0 //	reserved for BER
	boolean         = 1 // BOOLEAN
	integer         = 2 // INTEGER
	bitstring       = 3 // BIT STRING
	octetstring     = 4 // OCTET STRING
	null            = 5 // NULL
	oid             = 6 // OBJECT IDENTIFIER
	objdesc         = 7 // ObjectDescriptor
	external        = 8 //	INSTANCE OF, EXTERNAL
	real            = 9 // REAL
	enumerated      = 10 // ENUMERATED
	embedded        = 11 // EMBEDDED PDV
	utf8string      = 12 // UTF8String
	relativeoid     = 13 // RELATIVE-OID
	sequence        = 16 // SEQUENCE, SEQUENCE OF, Constructed
	set             = 17 ///SET, SET OF, Constructed
	numericstring   = 18 // NumericString
	printablestring = 19 // PrintableString
	t61string       = 20 // eletexString, T61String
	videotexstring  = 21 // VideotexString
	ia5string       = 22 // IA5String
	utctime         = 23 // UTCTime
	generalizedtime = 24 // GeneralizedTime
	graphicstring   = 25 // GraphicString
	visiblestring   = 26 // VisibleString, ISO646String
	generalstring   = 27 // GeneralString
	universalstring = 28 // UniversalString
	characterstring = 29 // CHARACTER STRING
	bmpstring       = 30 // BMPString
}

fn (t TagType) str() string {
	match t {
		.boolean { return 'boolean' }
		.integer { return 'integer' }
		.bitstring { return 'bitstring' }
		.octetstring { return 'octetstring' }
		.null { return 'null' }
		.oid { return 'oid' }
		.enumerated { return 'enumerated' }
		.utf8string { return 'utf8string' }
		.sequence { return 'sequence or sequence of' }
		.set { return 'set or set of' }
		.numericstring { return 'numericstring' }
		.printablestring { return 'printablestring' }
		.ia5string { return 'ia5string' }
		.utctime { return 'utctime' }
		.generalizedtime { return 'generalizedtime' }
		.visiblestring { return 'visiblestring' }
		else { return 'unsupported name' }
	}
}

// Maximum number of bytes to represent tag number, includes tag byte.
// For 5 bytes length, maximum bytes arrays to represent tag number is
// [u8(0x1f), 0xff, 0xff, 0xff, 0x7f] or 268435455 in base 128, so, its
// big enough to hold and represent different of tag number or type.
const max_tag_bytes_length = 5

// `new_tag` creates new tag with class `c`, with constructed or primitive form
// through `constructed` boolean flag, and tag `number`.
pub fn new_tag(c Class, constructed bool, number int) Tag {
	return Tag{
		class: c
		constructed: constructed
		number: number
	}
}

struct Tag {
mut:
	class       Class
	constructed bool
	number      int
}

fn (t Tag) equal(o Tag) bool {
	return t == o
}

fn (t Tag) is_constructed() bool {
	return t.constructed
}

fn (t Tag) is_primitive() bool {
	return !t.is_constructed()
}

fn (t Tag) is_universal() bool {
	return t.class == .universal
}

fn (t Tag) is_application() bool {
	return t.class == .application
}

fn (t Tag) is_context() bool {
	return t.class == .context
}

fn (t Tag) is_private() bool {
	return t.class == .private
}

fn (t Tag) is_sequence_tag() bool {
	return t.is_constructed() && t.number == int(TagType.sequence)
}

fn (t Tag) is_set_tag() bool {
	return t.is_constructed() && t.number == int(TagType.set)
}

// `calc_tag_length` calculates number or length of bytes needed to store tag number.
pub fn calc_tag_length(t Tag) int {
	n := if t.number < 0x1f { 1 } else { 1 + base128_int_length(i64(t.number)) }
	return n
}

// `serialize_tag` return bytes of serialized tag.
// This routine supports multi byte tag form to represents tag number that bigger than 31 (0x1f).
pub fn serialize_tag(mut dst []u8, tag Tag) []u8 {
	mut b := u8(tag.class) << 6
	if tag.constructed {
		b |= compound_mask
	}

	if tag.number >= 0x1f {
		b |= tagnumber_mask // 0x1f
		dst << b
		dst = encode_base128_int(mut dst, i64(tag.number))
	} else {
		b |= u8(tag.number)
		dst << b
	}

	return dst
}

// `read_tag` reading bytes of data from location (offset) `loc` to tag.
// It's return the tag structure and the next position (offset) `pos` for reading the length part.
pub fn read_tag(data []u8, loc int) !(Tag, int) {
	if data.len < 1 {
		return error('get ${data.len} bytes for reading tag, its not enough')
	}
	mut pos := loc
	if pos > data.len {
		return error('invalid len')
	}

	b := data[pos]
	pos += 1

	mut number := int(b & tagnumber_mask)
	constructed := b & compound_mask == compound_mask
	cls := int(b >> 6)

	if number == 0x1f {
		// we mimic go version of tag handling, only allowed `max_tag_bytes_length` bytes following
		// to represent tag number.
		number, pos = decode_base128_int(data, pos)!
		// pos is the next position to read next bytes, so check tag bytes length
		if (pos - loc - 1) >= asn1.max_tag_bytes_length {
			return error('tag bytes is too big')
		}
		if number < 0x1f {
			return error('non-minimal tag')
		}
	}
	tag := Tag{
		// casting numbers to enums, should be done inside `unsafe{}` blocks
		class: unsafe { Class(cls) }
		constructed: constructed
		number: number
	}
	return tag, pos
}

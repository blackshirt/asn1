// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// TagClass is ASN.1 tag class.
//
// To make sure ASN.1 encodings are not ambiguous, every ASN.1 type is associated with a tag.
// A tag consists of three parts: the tag class, tag form and the tag number.
// The following classes are defined in the standard.
pub enum TagClass {
	universal        = 0x00 // 0b00
	application      = 0x01 // 0b01
	context_specific = 0x02 // 0b10
	private          = 0x03 // 0b11
}

// from_int creates TagClass from integer v
pub fn TagClass.from_int(v int) !TagClass {
	match v {
		// vfmt off
		0x00 { return .universal }
		0x01 { return .application }
		0x02 { return .context_specific }
		0x03 { return .private }
		else {
			return error('Bad class number')
		}
		// vfmt on
	}
}

pub fn (c TagClass) str() string {
	match c {
		.universal { return 'UNIVERSAL' }
		.application { return 'APPLICATION' }
		.context_specific { return 'CONTEXT_SPECIFIC' }
		.private { return 'PRIVATE' }
	}
}

// vfmt off
// bit masking values for ASN.1 tag header
const tag_class_mask 	= 0xc0 // 192, bits 8-7
const constructed_mask 	= 0x20 //  32, bits 6
const tag_numher_mask 	= 0x1f //  32, bits 1-5
// vfmt on

// Maximum number of bytes to represent tag number, includes the tag byte.
// We impose limit on the tag number to be in range 0..16383. See comment on `TagNumber` type below.
// Its big enough to accomodate and represent different of yours own tag number.
// Its represents 2 bytes length where maximum bytes arrays to represent tag number
// in multibyte (long) form is `[u8(0x1f), 0xff, 0x7f]` or 16383 in base 128.
const max_tag_length = 3
const max_tag_number = 16383

// ASN.1 Tag Number
//
// ASN.1 imposes no limit on the tag number, but the NIST Stable Implementation Agreements (1991)
// and its European and Asian counterparts limit the size of tags to 16383.
// see https://www.oss.com/asn1/resources/asn1-faq.html#tag-limitation
type TagNumber = int

// from_int creates TagNumber from integer v. Its does not support to pass
// negative integer, its not make sense for now.
pub fn TagNumber.from_int(v int) !TagNumber {
	if v < 0 {
		return error('TagNumber: negative number')
	}
	if v > asn1.max_tag_number {
		return error('TagNumber: ${v} is too big, dont exceed ${asn1.max_tag_number}')
	}
	return TagNumber(v)
}

// bytes_len tells amount of bytes needed to store v in base 128
fn (v TagNumber) bytes_len() int {
	if v == 0 {
		return 1
	}
	mut n := v
	mut ret := 0

	for n > 0 {
		ret += 1
		n >>= 7
	}

	return ret
}

fn (v TagNumber) tag_number_length() int {
	// when number is greater than 31 (0x1f), its more bytes
	// to represent this number.
	len := if v < 0x1f { 1 } else { v.bytes_len() + 1 }
	return len
}

// pack_base128 serializes TagNumber v into bytes and append it into `to` in base 128
// the p of Params is not make sense here, its only for places holder for expandable things,
// when its has different meaning with standard, just ignore them now.
fn (v TagNumber) pack_base128(mut to []u8, p Params) {
	n := v.bytes_len()
	for i := n - 1; i >= 0; i-- {
		mut o := u8(v >> u32(i * 7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}

		to << o
	}
}

// unpack_from_asn1 deserializes bytes into TagNumber from loc offset in base 128.
// Its return deserialized TagNumber and next offset to process on.
fn TagNumber.decode(bytes []u8, loc i64, p Params) !(TagNumber, i64) {
	if loc > bytes.len {
		return error('TagNumber: invalid pos')
	}
	mut pos := loc
	mut ret := 0
	for s := 0; pos < bytes.len; s++ {
		ret <<= 7
		b := bytes[pos]

		if s == 0 && b == 0x80 {
			// requirement for DER encoding
			return error('TagNumber: integer is not minimally encoded')
		}

		ret |= b & 0x7f
		pos += 1

		if b & 0x80 == 0 {
			if ret > asn1.max_tag_number {
				return error('TagNumber: base 128 integer too large')
			}
			val := TagNumber.from_int(ret)!
			return val, pos
		}
	}
	return error('TagNumber: truncated base 128 integer')
}

// `universal_tag_type` transforrms this TagNumber into available Universal class of TagType,
// or return error if it is unknown number.
pub fn (v TagNumber) universal_tag_type() !TagType {
	// currently, only support Standard universal tag number
	if v > 36 {
		return error('TagNumber: unknown TagType number=${v}')
	}
	match v {
		// vfmt off
		0 { return .reserved } 
		1 {	return .boolean } 
		2 { return .integer	} 
		3 { return .bitstring } 
		4 { return .octetstring } 
		5 { return .null } 
		6 { return .oid } 
		7 { return .objdesc } 
		8 { return .external } 
		9 { return .real } 
		10 { return .enumerated } 
		11 { return .embedded } 
		12 { return .utf8string } 
		13 { return .relativeoid } 
		14 { return .time } 
		16 { return .sequence } 
		17 { return .set } 
		18 { return .numericstring } 
		19 { return .printablestring } 
		20 { return .t61string } 
		21 { return .videotexstring } 
		22 { return .ia5string } 
		23 { return .utctime } 
		24 { return .generalizedtime } 
		25 { return .graphicstring } 
		26 { return .visiblestring } 
		27 { return .generalstring } 
		28 { return .universalstring } 
		29 { return .characterstring } 
		30 { return .bmpstring } 
		31 { return .date } 
		32 { return .time_of_day } 
		33 { return .date_time } 
		34 { return .duration } 
		35 { return .i18_oid } 
		36 { return .relative_i18_oid } 
		// vfmt on
		else {
			return error('reserved or unknonw number')
		}
	}
}

// Standard UNIVERSAL tag number. Some of them was deprecated,
// so its not going to be supported on this module.
pub enum TagType {
	//	reserved for BER
	reserved = 0
	// BOOLEAN type
	boolean = 1
	// INTEGER type
	integer = 2
	// BIT STRING
	bitstring = 3
	// OCTET STRING
	octetstring = 4
	// NULL
	null = 5
	// OBJECT IDENTIFIER
	oid = 6
	// ObjectDescriptor
	objdesc = 7
	//	INSTANCE OF, EXTERNAL
	external = 8
	// REAL
	real = 9
	// ENUMERATED
	enumerated = 10
	// EMBEDDED PDV
	embedded = 11
	// UTF8String
	utf8string = 12
	// RELATIVE-OID
	relativeoid = 13
	// deprecated
	// 0x0f is reserved
	time = 14
	// SEQUENCE, SEQUENCE OF, Constructed
	sequence = 16
	///SET, SET OF, Constructed
	set = 17
	// NumericString
	numericstring = 18
	// PrintableString
	printablestring = 19
	// TeletexString, T61String
	t61string = 20
	// VideotexString
	videotexstring = 21
	// IA5String
	ia5string = 22
	// UTCTime
	utctime = 23
	// GeneralizedTime
	generalizedtime = 24
	// GraphicString
	graphicstring = 25
	// VisibleString, ISO646String
	visiblestring = 26
	// GeneralString
	generalstring = 27
	// UniversalString
	universalstring = 28
	// CHARACTER STRING
	characterstring = 29
	// BMPString
	bmpstring   = 30
	date        = 0x1f
	time_of_day = 0x20
	date_time   = 0x21
	duration    = 0x22
	// Internationalized OID
	i18_oid = 0x23
	// Internationalized Relative OID
	// Reserved 0x25 and above
	relative_i18_oid = 0x24
}

pub fn (t TagType) str() string {
	match t {
		.boolean { return 'BOOLEAN' }
		.integer { return 'INTEGER' }
		.bitstring { return 'BITSTRING' }
		.octetstring { return 'OCTETSTRING' }
		.null { return 'NULL' }
		.oid { return 'OID' }
		.objdesc { return 'OBJECT_DESCRIPTION' }
		.external { return 'EXTERNAL' }
		.real { return 'REAL' }
		.enumerated { return 'ENUMERATED' }
		.embedded { return 'EMBEDDED' }
		.utf8string { return 'UTF8STRING' }
		.relativeoid { return 'RELATIVEOID' }
		.time { return 'TIME' }
		.sequence { return 'SEQUENCE_OR_SEQUENCEOF' }
		.set { return 'SET_OR_SET_OF' }
		.numericstring { return 'NUMERICSTRING' }
		.printablestring { return 'PRINTABLESTRING' }
		.t61string { return 'T61STRING' }
		.videotexstring { return 'VIDEOTEXSTRING' }
		.ia5string { return 'IA5STRING' }
		.utctime { return 'UTCTIME' }
		.generalizedtime { return 'GENERALIZEDTIME' }
		.graphicstring { return 'GRAPHICSTRING' }
		.visiblestring { return 'VISIBLESTRING' }
		.generalstring { return 'GENERALSTRING' }
		.universalstring { return 'UNIVERSALSTRING' }
		.characterstring { return 'CHARACTERSTRING' }
		.bmpstring { return 'BMPSTRING' }
		else { return 'UNSUPPORTED_TAG_TYPE' }
	}
}

// Params is optional params passed to pack or unpacking
// of tag, length or ASN.1 element to drive how encoding works.
@[params]
pub struct Params {
pub mut:
	mode EncodingMode = .der
}

// encoding mode
pub enum EncodingMode {
	// Distinguished Encoding Rules (DER)
	der = 0
	// Basic Encoding Rules (BER)
	ber = 1
	// Octet Encoding Rules (OER)
	oer = 2
	// Packed Encoding Rules (PER)
	per = 3
	// XML Encoding Rules (XER)
	xer = 4
}

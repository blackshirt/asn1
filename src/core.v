// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import log
// TagClass is ASN.1 tag class.
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

fn (c TagClass) str() string {
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

// ASN1 Tag identifier handling

// Tag represents identifier of the ASN1 element (object)
// ASN.1 Tag number can be represented in two form, short form and long form.
// The short form for tag number below <= 30 and stored enough in single byte,
// where long form for tag number > 30, and stored in two or more bytes.
// See limit restriction comment above.
@[noinit]
pub struct Tag {
mut:
	class       TagClass = .universal
	constructed bool
	number      TagNumber
}

// `Tag.new` creates new ASN.1 tag identifier. Its accepts params of TagClass `cls`,
// the tag form in the form of constructed or primitive in `constructed` boolean flag, and the integer tag `number`.
pub fn Tag.new(cls TagClass, constructed bool, number int) !Tag {
	match cls {
		.universal {
			tnum := TagNumber.from_int(number)!
			if !tnum.valid_supported_universal_tagnum() {
				return error('Not a valid tag number for universal class=${number}')
			}
			univ_type := tnum.universal_tag_type()!
			// SEQUENCE (OF) or SET (OF) should constructed bit was set
			if univ_type == TagType.sequence || univ_type == TagType.set {
				if !constructed {
					return error('For SEQUENCE(OF) or SET(OF) type, should be in constructed form')
				}
			}
			tag := Tag{
				class:       cls
				constructed: constructed
				number:      tnum
			}
			return tag
		}
		.context_specific {
			// in .context_specific class, treats is as TaggedType in constructed form
			if !constructed {
				return error('Context Specific should be in constructed form')
			}
			tag := Tag{
				class:       cls
				constructed: constructed
				number:      TagNumber.from_int(number)!
			}
			return tag
		}
		else {
			// Otherwise, just returns as is
			tag := Tag{
				class:       cls
				constructed: constructed
				number:      TagNumber.from_int(number)!
			}
			return tag
		}
	}
}

// tag_class return the ASN.1 class of this tag
pub fn (t Tag) tag_class() TagClass {
	return t.class
}

// is_constructed tells us whether this tag is constructed or not
pub fn (t Tag) is_constructed() bool {
	return t.constructed
}

// tag_number return the tag nunber of this tag
pub fn (t Tag) tag_number() int {
	return t.number
}

// pack serializes tag t into bytes array
pub fn (t Tag) pack() ![]u8 {
	p := Params{}
	mut dst := []u8{}
	t.pack_with_params(mut dst, p)!
	return dst
}

// pack_with_params serializes tag into bytes array
fn (t Tag) pack_with_params(mut dst []u8, p Params) ! {
	// we currently only support .der or (stricter) .ber
	if p.rule != .der && p.rule != .ber {
		return error('Tag: unsupported rule')
	}
	// makes sure TagNumber is valid
	if t.number > asn1.max_tag_number {
		return error('Tag: tag number exceed limit')
	}

	// get the class type and constructed bit and build the bytes tag.
	// if the tag number > 0x1f, represented in long form required two or more bytes,
	// otherwise, represented in short form, fit in single byte.
	mut b := (u8(t.class) << 6) & asn1.tag_class_mask
	if t.constructed {
		b |= asn1.constructed_mask
	}
	// The tag is in long form
	if t.number >= 0x1f {
		b |= asn1.tag_numher_mask // 0x1f
		dst << b
		t.number.pack_base128(mut dst)
	} else {
		// short form
		b |= u8(t.number)
		dst << b
	}
}

// Tag.unpack tries to deserializes bytes into Tag. its return error on fails.
pub fn Tag.unpack(bytes []u8) !(Tag, i64) {
	// default params
	p := Params{}
	tag, next := Tag.unpack_with_params(bytes, 0, p)!
	return tag, next
}

// Tag.unpack_with_params deserializes bytes back into Tag structure start from `loc` offset.
// By default, its unpacks in .der encoding rule, if you want more control, pass your `Params`.
// Its return Tag and next offset to operate on, and return error if it fails to unpack.
fn Tag.unpack_with_params(bytes []u8, loc i64, p Params) !(Tag, i64) {
	// preliminary check
	if bytes.len < 1 {
		return error('Tag: bytes underflow')
	}
	if p.rule != .der && p.rule != .ber {
		return error('Tag: unsupported rule')
	}
	// when accessing byte at ofset `loc` within bytes, ie, `b := bytes[loc]`,
	// its maybe can lead to panic when the loc is not be checked.
	if loc >= bytes.len {
		return error('Tag: invalid pos')
	}
	mut pos := loc
	// first byte of tag bytes
	b := bytes[pos]
	pos += 1

	// First we get the first byte from the bytes, check and gets the class and constructed bits
	// and the tag number marker. If this marker == 0x1f, it tells whether the tag number is represented
	// in multibyte (long form), or short form otherwise.
	class := int((b & asn1.tag_class_mask) >> 6)
	constructed := b & asn1.constructed_mask == asn1.constructed_mask
	mut number := TagNumber.from_int(int(b & asn1.tag_numher_mask))!

	// check if this `number` is in long (multibyte) form, and interpretes more bytes as a tag number.
	if number == 0x1f {
		// we only allowed `max_tag_length` bytes following to represent tag number.
		number, pos = TagNumber.unpack(bytes, pos)!

		// pos is the next position to read next bytes, so check tag bytes length
		if pos >= asn1.max_tag_length + loc + 1 {
			return error('Tag: tag bytes is too long')
		}
		if number < 0x1f {
			// requirement for DER encoding.
			// TODO: the other encoding may remove this restriction
			return error('Tag: non-minimal tag')
		}
	}
	// build the tag
	tag := Tag.new(TagClass.from_int(class)!, constructed, number)!

	return tag, pos
}

// clone_with_class clones teh tag t into new tag with class is set to c
fn (mut t Tag) clone_with_class(c TagClass) Tag {
	mut new := t
	new.class = c
	return new
}

fn (mut t Tag) clone_with_tag(v int) !Tag {
	mut new := t
	val := TagNumber.from_int(v)!
	t.number = val
	return new
}

// packed_length calculates length of bytes needed to store the tag in .der rule.
fn (t Tag) packed_length() !int {
	p := Params{}
	n := t.packed_length_with_params(p)!
	return n
}

// `packed_length_with_params` calculates length of bytes needed to store tag number, include one byte
// marker that tells if the tag number is in long form (>= 0x1f)
fn (t Tag) packed_length_with_params(p Params) !int {
	if p.rule != .der && p.rule != .ber {
		return error('Tag: unsupported rule')
	}
	n := if t.number < 0x1f { 1 } else { 1 + t.number.bytes_len() }
	return n
}

// ASN.1 Tag Number
//
// ASN.1 imposes no limit on the tag number, but the NIST Stable Implementation Agreements (1991)
// and its European and Asian counterparts limit the size of tags to 16383.
// see https://www.oss.com/asn1/resources/asn1-faq.html#tag-limitation
type TagNumber = u32

// from_int creates TagNumber from integer v. Its does not support to pass
// negative integer, its not make sense for now.
pub fn TagNumber.from_int(v int) !TagNumber {
	if v < 0 {
		return error('TagNumber: negative number')
	}
	if v > asn1.max_tag_number {
		return error('TagNumber: ${v} is too big, dont exceed ${asn1.max_tag_number}')
	}
	return TagNumber(u32(v))
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

// pack_base128 serializes TagNumber v into bytes in base 128
fn (v TagNumber) pack_base128() ![]u8 {
	mut dst := []u8{}
	v.pack_base128_with_params(mut dst)!
	return dst
}

// pack_base128_with_params serializes TagNumber v into bytes in base 128
// The p params is not make sense here, its only for places holder for expandable things,
// when its has different meaning with standard, just ignore them now.
fn (v TagNumber) pack_base128_with_params(mut dst []u8, p Params) ! {
	n := v.bytes_len()
	// TODO: add support for other params
	for i := n - 1; i >= 0; i-- {
		mut o := u8(v >> u32(i * 7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}
		dst << o
	}
}

// TagNumber.unpack deserializes bytes into TagNumber from offset 0 in base 128.
// Its return deserialized TagNumber and next offset to process on.
fn TagNumber.unpack(bytes []u8) !(TagNumber, i64) {
	p := Params{}
	tnum, next := TagNUmber.unpack_with_params(bytes, 0, p)!
	return tnum, next
}

// unpack_with_params deserializes bytes into TagNumber from loc offset in base 128.
// Its return deserialized TagNumber and next offset to process on.
fn TagNUmber.unpack_with_params(bytes []u8, loc i64, p Params) !(TagNumber, i64) {
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

// Maximaum value of known universal type tag number, see `TagType`
const max_universal_tagnumber = 36

fn (v TagNUmber) valid_supported_universal_tagnum() bool {
	return v < asn1.max_universal_tagnumber
}

// `universal_tag_type` transforrms this TagNumber into available UNIVERSAL class of TagType,
// or return error if it is unknown number.
fn (v TagNumber) universal_tag_type() !TagType {
	// currently, only support Standard universal tag number
	if v > asn1.max_universal_tagnumber {
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
enum TagType {
	// vfmt off
	reserved 			= 0 	// reserved for BER
	boolean 			= 1 	// BOOLEAN type
	integer 			= 2 	// INTEGER type
	bitstring 			= 3 	// BIT STRING
	octetstring 		= 4 	// OCTET STRING
	null 				= 5 	// NULL
	oid 				= 6		// OBJECT IDENTIFIER
	objdesc 			= 7 	// OBJECT DESCRIPTOR
	external 			= 8 	// INSTANCE OF, EXTERNAL
	real 				= 9 	// REAL
	enumerated 			= 10 	// ENUMERATED
	embedded 			= 11 	// EMBEDDED PDV
	utf8string 			= 12 	// UTF8STRING
	relativeoid 		= 13 	// RELATIVE-OID
	// deprecated
	time 				= 14
	// 0x0f is reserved
	sequence 			= 16 	// SEQUENCE, SEQUENCE OF, Constructed
	set 				= 17 	// SET, SET OF, Constructed
	numericstring 		= 18 	// NUMERICSTRING
	printablestring 	= 19 	// PRINTABLESTRING
	t61string 			= 20 	// TELETEXSTRING, T61STRING
	videotexstring 		= 21 	// VIDEOTEXSTRING
	ia5string 			= 22 	// IA5STRING
	utctime 			= 23 	// UTCTIME
	generalizedtime 	= 24 	// GENERALIZEDTIME
	graphicstring 		= 25 	// GRAPHICSTRING
	visiblestring 		= 26 	// VISIBLESTRING, ISO646STRING
	generalstring 		= 27 	// GENERALSTRING
	universalstring 	= 28 	// UNIVERSALSTRING
	characterstring 	= 29 	// CHARACTER STRING
	bmpstring   		= 30 	// BMPSTRING
	// unsupported 
	date        		= 0x1f
	time_of_day 		= 0x20
	date_time   		= 0x21
	duration    		= 0x22
	// Internationalized OID
	i18_oid 			= 0x23
	// Internationalized Relative OID
	// Reserved 0x25 and above
	relative_i18_oid 	= 0x24
	// vfmt on
}

pub fn (t TagType) str() string {
	match t {
		.boolean { return 'BOOLEAN' }
		.integer { return 'INTEGER' }
		.bitstring { return 'BITSTRING' }
		.octetstring { return 'OCTETSTRING' }
		.null { return 'NULL' }
		.oid { return 'OID' }
		.objdesc { return 'OBJECT_DESCRIPTOR' }
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
	rule EncodingRule = .der
}

// encoding rule
pub enum EncodingRule {
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

// custom Error
struct SyntaxError {
	Error
mut:
	msg string
}

fn (se &SyntaxError) msg() string {
	return se.msg
}

// syntaxError allocates a new ParseError,
fn syntax_error(msg string, opts &FieldOptions) &SyntaxError {
	se := &SyntaxError{
		msg: msg
	}
	return se
}

// Context keeps options that affect the ASN.1 encoding and decoding
struct Context {
mut:
	logger &log.Logger = log.new_thread_safe_log()
	// rule drive the ASN.1 context
	rule EncodingRule  = .der
	opt  &FieldOptions = unsafe { nil }
}

fn Context.new() &Context {
	return &Context{}
}

fn (mut ctx Context) with_logger(logger &log.Logger) &Context {
	ctx.logger = logger
	return ctx
}

fn (mut ctx Context) with_rule(rule EncodingRule) &Context {
	ctx.rule = rule
	return ctx
}

struct FieldOptions {
mut:
	universal     bool
	application   bool
	explicit      bool
	private       bool
	indefinite    bool
	optional      bool
	set           bool
	tagnum        &int = unsafe { nil }
	default_value &int = unsafe { nil }
	string_type   int
	time_type     int
	choice        &string = unsafe { nil }
	omit_empty    bool
}

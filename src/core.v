// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import log
// TagClass is ASN.1 tag class.
// To make sure ASN.1 encodings are not ambiguous, every ASN.1 type is associated with a tag.
// A tag consists of three parts: the tag class, tag form and the tag number.
// The following classes are defined in the ASN.1 standard.

pub enum TagClass {
	universal        = 0x00 // 0b00
	application      = 0x01 // 0b01
	context_specific = 0x02 // 0b10
	private          = 0x03 // 0b11
}

// from_int creates TagClass from integer v
fn TagClass.from_int(v int) !TagClass {
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

fn TagClass.from_string(s string) !TagClass {
	match s {
		'universal' {
			return .universal
		}
		'private' { return .private }
		.application {return .application}
		'context_specific'  {return .Context}
		else {return error('bad class string')}
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
const tag_number_mask 	= 0x1f //  31, bits 1-5
// vfmt on

// Maximum number of bytes to represent tag number, includes the tag byte.
// ASN.1 imposes no limit on the tag number, but the NIST Stable Implementation Agreements (1991)
// and its European and Asian counterparts limit the size of tags to 16383.
// see https://www.oss.com/asn1/resources/asn1-faq.html#tag-limitation
// We impose limit on the tag number to be in range 0..16383.
// Its big enough to accomodate and represent different of yours own tag number.
// Its represents 2 bytes length where maximum bytes arrays to represent tag number
// in multibyte (long) form is `[u8(0x1f), 0xff, 0x7f]` or 16383 in base 128.
const max_tag_length = 3
const max_tag_number = 16383

// Maximum value for UNIVERSAL class tag number, see `TagType`,
// Tag number above this number should be considered to other class, PRIVATE, CONTEXT_SPECIFIC or APPLICATION class.
const max_universal_tagnumber = 255

// ASN.1 Tag identifier handling
//
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
	number      u32
}

// `Tag.new` creates new ASN.1 tag identifier. Its accepts params of TagClass `cls`,
// the tag form in the form of constructed or primitive in `constructed` boolean flag, and the integer tag `number`.
pub fn Tag.new(cls TagClass, constructed bool, number int) !Tag {
	if number < 0 || number > max_tag_number {
		return error('Unallowed tag number, ${number} exceed limit')
	}
	match cls {
		.universal {
			if number > max_universal_tagnumber {
				return error('Not a valid tag number for universal class=${number}')
			}
			// SEQUENCE (OF) or SET (OF) should be in constructed form
			if number == int(TagType.sequence) || number == int(TagType.set) {
				if !constructed {
					return error('For SEQUENCE(OF) or SET(OF) type, should be in constructed form')
				}
			}
			tag := Tag{
				class:       cls
				constructed: constructed
				number:      tagnum_from_int(number)!
			}
			return tag
		}
		.context_specific {
			// in CONTEXT_SPECIFIC class, treats is as TaggedType in constructed form
			if !constructed {
				return error('Context Specific should be in constructed form')
			}
			tag := Tag{
				class:       cls
				constructed: constructed
				number:      tagnum_from_int(number)!
			}
			return tag
		}
		else {
			// Otherwise, just returns as is
			tag := Tag{
				class:       cls
				constructed: constructed
				number:      tagnum_from_int(number)!
			}
			return tag
		}
	}
}

// tagnum_from_int creates tag number from regular integer.
// Its just doing check and wrapping on the passed integer
fn tagnum_from_int(v int) !u32 {
	if v < 0 {
		return error('Negative number for tag number was not allowed')
	}
	if v > max_tag_number {
		return error('Number bigger than max allowed tag number')
	}
	return u32(v)
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

// encode serializes tag t into bytes array with default context
pub fn (t Tag) encode(mut dst []u8) ! {
	ctx := Context{}
	t.encode_with_context(mut dst, ctx)!
}

// encode_with_context serializes tag into bytes array
fn (t Tag) encode_with_context(mut dst []u8, ctx Context) ! {
	// we currently only support .der or (stricter) .ber
	if ctx.rule != .der && ctx.rule != .ber {
		return error('Tag: unsupported rule')
	}
	// makes sure tag number is valid
	if t.number > max_tag_number {
		return error('Tag: tag number exceed limit')
	}

	// get the class type and constructed bit and build the bytes tag.
	// if the tag number > 0x1f, represented in long form required two or more bytes,
	// otherwise, represented in short form, fit in single byte.
	mut b := (u8(t.class) << 6) & tag_class_mask
	if t.constructed {
		b |= constructed_mask
	}
	// The tag is in long form
	if t.number >= 0x1f {
		b |= tag_number_mask // 0x1f
		dst << b
		t.to_bytes_in_base128(mut dst)!
	} else {
		// short form
		b |= u8(t.number)
		dst << b
	}
}

// Tag.decode tries to deserializes bytes into Tag. its return error on fails.
pub fn Tag.decode(bytes []u8) !(Tag, i64) {
	tag, next := Tag.decode_from_offset(bytes, 0)!
	return tag, next
}

// Tag.decode tries to deserializes bytes into Tag. its return error on fails.
fn Tag.decode_from_offset(bytes []u8, pos i64) !(Tag, i64) {
	// default params
	ctx := Context{}
	tag, next := Tag.decode_with_context(bytes, pos, ctx)!
	return tag, next
}

// Tag.decode_with_context deserializes bytes back into Tag structure start from `loc` offset.
// By default, its decodes in .der encoding rule, if you want more control, pass your `Params`.
// Its return Tag and next offset to operate on, and return error if it fails to decode.
fn Tag.decode_with_context(bytes []u8, loc i64, ctx Context) !(Tag, i64) {
	// preliminary check
	if bytes.len < 1 {
		return error('Tag: bytes underflow')
	}
	if ctx.rule != .der && ctx.rule != .ber {
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
	class := int((b & tag_class_mask) >> 6)
	constructed := b & constructed_mask == constructed_mask
	mut number := tagnum_from_int(int(b & tag_number_mask))!

	// check if this `number` is in long (multibyte) form, and interpretes more bytes as a tag number.
	if number == 0x1f {
		// we only allowed `max_tag_length` bytes following to represent tag number.
		number, pos = Tag.read_tagnum(bytes, pos)!

		// pos is the next position to read next bytes, so check tag bytes length
		if pos >= max_tag_length + loc + 1 {
			return error('Tag: tag bytes is too long')
		}
		if number < 0x1f && ctx.rule == .der {
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
	val := tagnum_from_int(v)!
	t.number = val
	return new
}

// bytes_len tells amount of bytes needed to store tag in base 128
fn (t Tag) bytes_len() int {
	if t.number == 0 {
		return 1
	}
	mut n := t.number
	mut ret := 0

	for n > 0 {
		ret += 1
		n >>= 7
	}

	return ret
}

// tag_size informs us how many bytes needed to store this tag includes one byte marker if in long form.
fn (t Tag) tag_size() int {
	// when number is greater than 31 (0x1f), its need more bytes
	// to represent this number, includes one byte marker for long form tag
	len := if t.number < 0x1f { 1 } else { t.bytes_len() + 1 }
	return len
}

// to_bytes_in_base128 serializes tag number into bytes in base 128
fn (t Tag) to_bytes_in_base128(mut dst []u8) ! {
	n := t.bytes_len()
	for i := n - 1; i >= 0; i-- {
		mut o := u8(t.number >> u32(i * 7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}
		dst << o
	}
}

// Tag.read_tagnum read the tag number from bytes from offset pos in base 128.
// Its return deserialized Tag number and next offset to process on.
fn Tag.read_tagnum(bytes []u8, pos i64) !(u32, i64) {
	ctx := Context{}
	tnum, next := Tag.read_tagnum_with_context(bytes, pos, ctx)!
	return tnum, next
}

// read_tagnum_with_context is the main routine to read the tag number part in the bytes source,
// start from offset loc in base 128. Its return the tag number and next offset to process on, or error on fails.
fn Tag.read_tagnum_with_context(bytes []u8, loc i64, ctx Context) !(u32, i64) {
	if loc > bytes.len {
		return error('Tag number: invalid pos')
	}
	mut pos := loc
	mut ret := 0
	for s := 0; pos < bytes.len; s++ {
		ret <<= 7
		b := bytes[pos]

		if s == 0 && b == 0x80 {
			if ctx.rule == .der {
				// requirement for DER encoding
				return error('Tag number: integer is not minimally encoded')
			}
		}
		ret |= b & 0x7f
		pos += 1

		if b & 0x80 == 0 {
			if ret > max_tag_number {
				return error('Tag number: base 128 integer too large')
			}
			if ret < 0 {
				return error('Negative tag number')
			}
			val := u32(ret)
			return val, pos
		}
	}
	return error('Tag: truncated base 128 integer')
}

fn (t Tag) valid_supported_universal_tagnum() bool {
	return t.class == .universal && t.number < max_universal_tagnumber
}

// `universal_tag_type` transforrms this TagNumber into available UNIVERSAL class of TagType,
// or return error if it is unknown number.
fn (t Tag) universal_tag_type() !TagType {
	// currently, only support Standard universal tag number
	if t.number > max_universal_tagnumber {
		return error('Tag number: unknown TagType number=${t.number}')
	}
	match t.class {
		.universal {
			match t.number {
				// vfmt off
				0 { return .reserved }
				1 { return .boolean }
				2 { return .integer }
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
				else {
					return error('reserved or unknonw number')
				}
				// vfmt on
			}
		}
		else {
			return error('Not universal class type')
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

// Params is optional params passed to encode or decodeing
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
@[params]
struct Context {
mut:
	logger &log.Logger = log.new_thread_safe_log()
	// rule drive the ASN.1 encoding/decoding
	rule EncodingRule = .der
	// make sense when encoding or decoding ASN.1 Element
	opt &FieldOptions = unsafe { nil }
}

fn Context.new() &Context {
	return &Context{}
}

@[noinit]
struct FieldOptions {
mut:
	// wrapper class
	wrapper TagClass
	// set to true when should be optional element
	optional bool
	// set to true when optional element has default value
	has_default bool
	// treated as set / set of
	set bool
	// tag number for wrapper element
	tagnum &int = unsafe { nil }
	// default value for optional element when has_default value is true
	default_value &Element = unsafe { nil }
	omit_empty    bool
}

/*
// encode_with_context encode with context
fn encode_with_context(el Element, ctx Context) ![]u8 {
}

// encode_with_context encodes element with default context
fn encode(el Element) ![]u8 {
	return el.encode()!
}

// decode_with_context decodes bytes with context
fn decode_with_context[T](src []u8, ctx Context) !(T, i64) {}

// decode_with_context decodes bytes with default context
fn decode[T](src []u8, ctx Context) !(T, i64) {}

fn parse_optional[T](src []u8) ?(T, i64) {}

// is_fullfill_asn1_element checks whether a generic element T meet required method of Element interface
fn is_fullfill_asn1_element[T]() bool {
	$if T is Element {
		return true
	}
	return false
}
*/

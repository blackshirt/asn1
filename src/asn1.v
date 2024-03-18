// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Class is ASN.1 tag class.
// Currently most of universal class supported in this module, with limited support for other class.
pub enum Class {
	universal   = 0x00
	application = 0x01
	context     = 0x02
	private     = 0x03
}

const class_mask = 0xc0 // 192, bits 7-8

const compound_mask = 0x20 //  32, bits 6

const tagnumber_mask = 0x1f //  32, bits 1-5

// Encoder is a main interrface that wraps ASN.1 encoding functionality.
// Most of basic types in this module implements this interface.
pub interface Encoder {
	// tag of the underlying ASN.1 object
	tag() Tag
	// length of ASN.1 object (without tag and length part)
	length() int
	// length of encoded bytes of the object (included tag and length part)
	size() int
	// Serializes object to bytes array with DER encoding
	encode() ![]u8
}

// der_decode is main routine to do parsing of DER encoded data.
// Its accepts bytes arrays encoded in DER in `src` params and returns `Encoder` interfaces object,
// so, you should cast it to get underlying type.
// By default, in context specific class, its try to read as tagged object, whether its explicit or implicit.
// TODO: more robust parsing function to handle specific use cases.
pub fn der_decode(src []u8) !Encoder {
	tag, pos := read_tag(src, 0)!
	length, next := decode_length(src, pos)!
	if src.len > next + length {
		return error('malformed bytes, contains discarded bytes')
	}
	// remaining is a contents
	// contents := src[next..next + length]
	contents := read_bytes(src, next, length)!
	match tag.class {
		.universal {
			if tag.constructed {
				return parse_compound_element(tag, contents)!
			}

			return parse_primitive_element(tag, contents)!
		}
		.application {
			return new_asn_object(.application, tag.constructed, tag.number, contents)
		}
		.context {
			if tag.constructed {
				return read_explicit_context(tag, contents)!
			}
			return read_implicit_context(tag, contents)!
		}
		.private {
			return new_asn_object(.private, tag.constructed, tag.number, contents)
		}
	}
}

fn parse_primitive_element(tag Tag, contents []u8) !Encoder {
	if tag.is_constructed() {
		return error('not primitive tag ')
	}

	match tag.number {
		int(TagType.boolean) {
			return new_boolean_from_bytes(contents)
		}
		int(TagType.integer) {
			return new_integer_from_bytes(contents)
		}
		int(TagType.bitstring) {
			return new_bitstring_from_bytes(contents)
		}
		int(TagType.octetstring) {
			return new_octetstring(contents.bytestr())
		}
		int(TagType.null) {
			return new_null()
		}
		int(TagType.oid) {
			return new_oid_from_bytes(contents)!
		}
		int(TagType.numericstring) {
			return new_numeric_string(contents.bytestr())
		}
		int(TagType.printablestring) {
			return new_printable_string(contents.bytestr())
		}
		int(TagType.ia5string) {
			return new_ia5string(contents.bytestr())
		}
		int(TagType.utf8string) {
			return new_utf8string(contents.bytestr())
		}
		int(TagType.visiblestring) {
			return new_visiblestring(contents.bytestr())
		}
		int(TagType.utctime) {
			return new_utctime(contents.bytestr())
		}
		// TODO:
		//   - add other type
		//   - relaxed parsing by return raw asn1 object.
		else {
			return ASN1Object{
				tag: tag
				values: contents
			}
		}
	}
}

fn parse_compound_element(tag Tag, contents []u8) !Encoder {
	if !tag.is_constructed() {
		return error('not constructed tag')
	}

	match true {
		tag.is_sequence_tag() {
			return parse_seq(tag, contents)!
		}
		tag.is_set_tag() {
			return parse_set(tag, contents)!
		}
		tag.is_context() {
			return read_explicit_context(tag, contents)!
		}
		else {
			return new_asn_object(tag.class, tag.constructed, tag.number, contents)
		}
	}
}

// contents gets the contents (values) part of ASN.1 object, that is,
// bytes values of the object  without tag and length parts.
pub fn (enc Encoder) contents() ![]u8 {
	bytes := enc.encode()!

	// actual length bytes of data
	length := enc.length()
	if length == 0 {
		return []u8{}
	}
	// length of encoded bytes included header
	size := enc.size()

	// header length
	hdr := size - length
	out := read_bytes(bytes, hdr, length)!
	return out
}

// Cast function.
// Its cast encoder type to real instance type.

// as_sequence cast encoder to sequence
pub fn (e Encoder) as_sequence() !Sequence {
	if e is Sequence {
		// without dereferencing, its result in error: error: fn `as_sequence` expects you to return
		// a non reference type `!asn1.Sequence`, but you are returning `&asn1.Sequence` instead
		return *e
	}
	return error('not sequence type')
}

// as_set cast encoder to set
pub fn (e Encoder) as_set() !Set {
	if e is Set {
		return *e
	}
	return error('not set type')
}

// as_boolean cast encoder to ASN.1 boolean
pub fn (e Encoder) as_boolean() !Boolean {
	if e is Boolean {
		return *e
	}
	return error('not boolean type')
}

// as_integer cast encoder to ASN.1 integer
pub fn (e Encoder) as_integer() !AsnInteger {
	if e is AsnInteger {
		return *e
	}
	return error('not integer type')
}

// as_bitstring cast encoder to ASN.1 bitstring
pub fn (e Encoder) as_bitstring() !BitString {
	if e is BitString {
		return *e
	}
	return error('not bitstring type')
}

// as_octetstring cast encoder to ASN.1 OctetString
pub fn (e Encoder) as_octetstring() !OctetString {
	if e is OctetString {
		return *e
	}
	return error('not octetstring type')
}

// as_null cast encoder to ASN.1 null type
pub fn (e Encoder) as_null() !Null {
	if e is Null {
		return *e
	}
	return error('not null type')
}

// as_oid cast encoder to ASN.1 object identifier type.
pub fn (e Encoder) as_oid() !Oid {
	if e is Oid {
		return *e
	}
	return error('not oid type')
}

// as_enumerated cast encoder to ASN.1 enumerated type.
fn (e Encoder) as_enumerated() !Enumerated {
	if e is Enumerated {
		return *e
	}
	return error('not enumerated type')
}

// as_utf8string cast encoder to ASN.1 UTF8String.
pub fn (e Encoder) as_utf8string() !UTF8String {
	if e is UTF8String {
		return *e
	}
	return error('not utf8string type')
}

// as_numericstring cast encoder to ASN.1 NumericString.
pub fn (e Encoder) as_numericstring() !NumericString {
	if e is NumericString {
		return *e
	}
	return error('not numericstring type')
}

// as_printablestring cast encoder to ASN.1 PrintableString.
pub fn (e Encoder) as_printablestring() !PrintableString {
	if e is PrintableString {
		return *e
	}
	return error('not printablestring type')
}

// as_ia5string cast encoder to ASN.1 IA5String.
pub fn (e Encoder) as_ia5string() !IA5String {
	if e is IA5String {
		return *e
	}
	return error('not ia5string type')
}

// as_visiblestring cast encoder to ASN.1 VisibleString.
pub fn (e Encoder) as_visiblestring() !VisibleString {
	if e is VisibleString {
		return *e
	}
	return error('not visiblestring type')
}

// as_utctime cast encoder to ASN.1 UTCTime.
pub fn (e Encoder) as_utctime() !UTCTime {
	if e is UTCTime {
		return *e
	}
	return error('not utctime type')
}

// as_generalizedtime cast encoder to ASN.1 GeneralizedTime.
pub fn (e Encoder) as_generalizedtime() !GeneralizedTime {
	if e is GeneralizedTime {
		return *e
	}
	return error('not generalizedtime type')
}

// length gets the bytes length of multi encoder.
fn (enc []Encoder) length() int {
	mut length := 0
	for obj in enc {
		n := obj.size()
		length += n
	}
	return length
}

// encode serializes multi encoder objects to bytes arrays.
fn (enc []Encoder) encode() ![]u8 {
	mut dst := []u8{}
	for e in enc {
		obj := e.encode()!
		dst << obj
	}
	return dst
}

// add encoder to existing encoder arrays.
pub fn (mut enc []Encoder) add(e Encoder) {
	enc << e
}

// add multi encoder to existing encoder arrays.
pub fn (mut enc []Encoder) add_multi(es []Encoder) {
	enc << es
}

// ASN1Object is generic ASN.1 Object representation.
// Its implements Encoder, so it can be used
// to support other class of der encoded ASN.1 object
// other than universal class supported in this module.
struct ASN1Object {
	tag    Tag  // tag of the ASN.1 object
	values []u8 // unencoded values of the object.
}

// `new_asn_object` creates new ASN.1 Object
pub fn new_asn_object(cls Class, constructed bool, tagnum int, values []u8) ASN1Object {
	return ASN1Object{
		tag: Tag{
			class: cls
			constructed: constructed
			number: tagnum
		}
		values: values
	}
}

pub fn (obj ASN1Object) tag() Tag {
	return obj.tag
}

pub fn (obj ASN1Object) length() int {
	return obj.values.len
}

pub fn (obj ASN1Object) size() int {
	mut size := 0
	tag := obj.tag()

	tg := calc_tag_length(tag)
	size += tg

	ln := calc_length_of_length(obj.length())
	size += int(ln)

	size += obj.length()

	return size
}

// encode serialize ASN.1 object to bytes array. its return error on fail.
pub fn (obj ASN1Object) encode() ![]u8 {
	return serialize_asn_object(obj)
}

pub fn ASN1Object.decode(src []u8) !ASN1Object {
	if src.len < 2 {
		return error('ASN1Object: underflow')
	}
	// raw tag
	tag, pos := read_tag(src, 0)!
	if pos > src.len {
		return error('truncated input')
	}

	length, next := decode_length(src, pos)!
	if next > src.len || next + length > src.len {
		return error('truncated input')
	}
	bytes := read_bytes(src, next, length)!

	return ASN1Object{
		tag: tag
		values: bytes
	}
}

fn serialize_asn_object(obj ASN1Object) ![]u8 {
	mut dst := []u8{}

	serialize_tag(mut dst, obj.tag())
	serialize_length(mut dst, obj.length())

	dst << obj.values

	return dst
}

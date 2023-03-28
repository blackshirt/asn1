// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Class is ASN.1 tag class.
// Currently most of universal class supported in this module, with limited support for other class.
pub enum Class {
	universal = 0x00
	application = 0x01
	context = 0x02
	private = 0x03
}

const (
	class_mask     = 0xc0 // 192, bits 7-8
	compound_mask  = 0x20 //  32, bits 6
	tagnumber_mask = 0x1f //  32, bits 1-5
)

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

// contents gets the contents (values) part of ASN.1 object, that is,
// bytes values of the object  without tag and length parts.
pub fn (enc Encoder) contents() ![]u8 {
	bytes := enc.encode()!

	// actual length bytes of data
	length := enc.length()

	// length of encoded bytes included header
	size := enc.size()

	// header length
	hdr := size - length
	out := read_bytes(bytes, hdr, length)!
	return out
}

fn (e Encoder) as_sequence() !Sequence {
	if e is Sequence {
		return *e
	}
	return error('not sequence')
}

fn (e Encoder) as_boolean() !AsnBoolean {
	if e is AsnBoolean {
		return *e
	}
	return error('not boolean type')
}

fn (e Encoder) as_integer() !AsnInteger {
	if e is AsnInteger {
		return *e
	}
	return error('not integer type')
}

fn (e Encoder) as_bitstring() !BitString {
	if e is BitString {
		return *e
	}
	return error('not bitstring type')
}

fn (e Encoder) as_octetstring() !OctetString {
	if e is OctetString {
		return *e
	}
	return error('not octetstring type')
}

fn (e Encoder) as_null() !Null {
	if e is Null {
		return *e
	}
	return error('not null type')
}

fn (e Encoder) as_enumerated() !Enumerated {
	if e is Enumerated {
		return *e
	}
	return error('not enumerated type')
}

fn (e Encoder) as_utf8string() !UTF8String {
	if e is UTF8String {
		return *e
	}
	return error('not utf8string type')
}

fn (e Encoder) as_numericstring() !NumericString {
	if e is NumericString {
		return *e
	}
	return error('not numericstring type')
}

fn (e Encoder) as_printablestring() !PrintableString {
	if e is PrintableString {
		return *e
	}
	return error('not printablestring type')
}

fn (e Encoder) as_ia5string() !IA5String {
	if e is IA5String {
		return *e
	}
	return error('not ia5string type')
}

fn (e Encoder) as_visiblestring() !VisibleString {
	if e is VisibleString {
		return *e
	}
	return error('not visiblestring type')
}

fn (e Encoder) as_utctime() !UtcTime {
	if e is UtcTime {
		return *e
	}
	return error('not utctime type')
}

fn (e Encoder) as_generalizedtime() !GeneralizedTime {
	if e is GeneralizedTime {
		return *e
	}
	return error('not generalizedtime type')
}

fn (e Encoder) as_oid() !Oid {
	if e is Oid {
		return *e
	}
	return error('not oid type')
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
fn (mut enc []Encoder) add(e Encoder) {
	enc << e
}

// add multi encoder to existing encoder arrays.
fn (mut enc []Encoder) add_multi(es []Encoder) {
	enc << es
}

// AsnObject is generic ASN.1 Object representation.
// Its implements Encoder, so it can be used
// to support other class of der encoded ASN.1 object
// other than universal class supported in this module.
pub struct AsnObject {
	tag    Tag  // tag of the ASN.1 object
	values []u8 // unencoded values of the object.
}

// `new_asn_object` creates new ASN.1 Object
pub fn new_asn_object(cls Class, constructed bool, tagnum int, values []u8) AsnObject {
	return AsnObject{
		tag: Tag{
			class: cls
			constructed: constructed
			number: tagnum
		}
		values: values
	}
}

pub fn (obj AsnObject) tag() Tag {
	return obj.tag
}

pub fn (obj AsnObject) length() int {
	return obj.values.len
}

pub fn (obj AsnObject) size() int {
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
pub fn (obj AsnObject) encode() ![]u8 {
	return serialize_asn_object(obj)
}

fn serialize_asn_object(obj AsnObject) ![]u8 {
	mut dst := []u8{}

	serialize_tag(mut dst, obj.tag())
	serialize_length(mut dst, obj.length())

	dst << obj.values

	return dst
}

// is_allhave_same_tag checks whether all object in Encoder arrays
// have the same tag value.
fn is_allhave_same_tag(objects []Encoder) bool {
	if objects.len < 1 {
		return false
	}

	tag0 := objects[0].tag()
	return objects.all(it.tag() == tag0)
}

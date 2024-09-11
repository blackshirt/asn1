// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// This file contains structures and routines for handling ASN.1 Element.
// Its includes:
// 	- basic Element interface, for support ASN.1 element in more generic way
//	- arrays of ELement in the form of ElementList
//	- basic raw element in the RawElement structure, for handling arbitrary class
//	  and other undefined (unsupported) generic ASN.1 Element in this module.
//	- others structures, likes an Choice, AnyDefinedBy, Optional for representing other
//	  element

// Element represents a generic ASN.1 Element.
// Most of the standard Universal class element defined on this module
// satisfies this interface. This interface was also expanded by methods
// defined on this interface.
pub interface Element {
	// tag tells the identity of this Element.
	tag() Tag
	// payload tells the raw payload (values) of this Element.
	payload() []u8
}

// FIXME: its not tested
// from_object[T] transforms and creates a new Element from generic type (maybe universal type, like an OctetString).
// Its accepts generic element t that you should pass to this function. You should make sure if this element implements
// required methods of the Element, or an error would be returned.
// Examples:
// ```v
// oc := asn1.OctetString.from_string("xxx")!
// el := Element.from_object[OctetString](oc)!
// ```
// and then treats your OctetString as an Element
pub fn Element.from_object[T](t T) !Element {
	return t
}

// into_object[T] transforms and tries to cast element el into generic object T
// if the element not holding object T, it would return error.
// NOTE: Not tested
// Examples:
// ```v
// oc := asn1.OctetString.from_string("xxx")!
// el := Element.from_object[OctetString](oc)!
//
// // cast back the element into OctetString
// os := el.into_object[OctetString]()!
// ```
// and then treats os as an OctetString
pub fn (el Element) into_object[T]() !T {
	if el is T {
		return *el
	}
	return error('Element el does not holding T')
}

// length returns the length of the payload of this element.
pub fn (el Element) length() int {
	return el.payload().len
}

pub fn (el Element) encode() ![]u8 {
	ctx := Context{}
	return el.encode_with_params(ctx)!
}

// encode_with_params serializes this el Element into bytes and appended to `dst`.
// Its accepts optional ctx Context.
fn (el Element) encode_with_params(mut dst []u8, ctx Context) ! {
	// we currently only support .der or (stricter) .ber
	if ctx.rule != .der && ctx.rule != .ber {
		return error('Element: unsupported rule')
	}
	if el.tag() == none {
		// optional element, do nothing
		return
	}
	elt := el.tag().pack_with_params(ctx)!
	dst << elt
	payload := el.payload()
	length := Length.from_i64(payload.len)!
	lout := length.pack_with_params(ctx)!
	dst << lout
	dst << payload
}

pub fn (el Element) packed_length() !int {
	ctx := Context{}
	n := el.packed_length_with_params(ctx)!
	return n
}

// packed_length_with_params informs us the length of how many bytes when this el Element
// was serialized into bytes.
fn (el Element) packed_length_with_params(ctx Context) !int {
	// when this element has none tag is set, its mean nothing,
	// just return 0 instead
	if el.tag() == none {
		return 0
	}
	mut n := 0
	n += el.tag().packed_length_with_params(ctx)!
	payload := el.payload()
	length := Length.from_i64(payload.len)!
	n += length.packed_length_with_params(ctx)!
	n += payload.len

	return n
}

pub fn Element.decode(src []u8) (Element, i64) {
	ctx := Context{}
	el, pos := Element.decode_with_params(src, 0, ctx)!
	return el, pos
}

// decode deserializes back bytes in src from offet `loc` into Element.
// Basically, its tries to parse a Universal class Elememt when it is possible.
// Other class parsed as a RawElement.
fn Element.decode_with_params(src []u8, loc i64, ctx Context) !(Element, i64) {
	raw, next := RawElement.decode(src, loc, ctx)!
	bytes := raw.payload

	match raw.tag.tag_class() {
		.universal {
			if raw.tag.is_constructed() {
				return parse_constructed_element(raw.tag, bytes)!, next
			}
			return parse_primitive_element(raw.tag, bytes)!, next
		}
		// other classes parsed as a RawElement
		else {
			return RawElement.new(raw.tag, bytes), next
		}
	}
}

fn (el Element) expect_tag(t Tag) bool {
	return el.tag() == t
}

// equal_with checks whether this two element equal and holds the same tag and content
fn (el Element) equal_with(other Element) bool {
	a := el.payload()
	b := other.payload()
	return el.tag() == other.tag() && a == b
}

fn (el Element) as_raw_element(ctx Context) !RawElement {
	re := RawElement.new(el.tag(), el.payload(ctx)!)
	return re
}

fn (el Element) expect_tag_class(c TagClass) bool {
	return el.tag().tag_class() == c
}

fn (el Element) expect_tag_form(constructed bool) bool {
	return el.tag().is_constructed() == constructed
}

fn (el Element) expect_tag_type(t TagType) bool {
	typ := el.tag().number.universal_tag_type() or { panic('unsupported tag type') }
	return typ == t
}

fn (el Element) expect_tag_number(number int) bool {
	tagnum := el.tag().tag_number()
	return int(tagnum) == number
}

// ElementList is arrays of ELement
type ElementList = []Element

// ElementList.from_bytes parses bytes in src as series of Element or return error on fails
pub fn ElementList.from_bytes(src []u8, ctx Context) ![]Element {
	mut els := []Element{}
	if src.len == 0 {
		// empty list
		return els
	}
	mut i := i64(0)
	for i < src.len {
		el, pos := Element.decode(src, i)!
		els << el
		i += pos
	}
	if i > src.len {
		return error('i > src.len')
	}
	if i < src.len {
		return error('The src contains unprocessed bytes')
	}
	return els
}

// hold_different_tag checks whether this array of Element
// contains any different tag, benefit for checking whether the type
// with this elements is sequence or sequence of type.
pub fn (els []Element) hold_different_tag() bool {
	// if els has empty length we return false, so we can treat
	// it as a regular sequence or set.
	if els.len == 0 {
		return false
	}
	// when this return true, there is nothing in elements
	// has same tag for all items, ie, there are some item
	// in the elements hold the different tag.
	tag0 := els[0].tag()
	return els.any(it.tag() != tag0)
}

// contains checks whether this array of Element contains the Element el
pub fn (els []Element) contains(el Element) bool {
	for e in els {
		if !el.equal_with(el) {
			return false
		}
	}
	return true
}

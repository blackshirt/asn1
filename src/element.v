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
	// tag tells the ASN.1 identity of this Element.
	tag() Tag
	// payload tells the payload (values) of this Element.
	// The element's size was calculated implicitly from payload.len
	// Its depends on the tag how interpretes this payload.
	payload() ![]u8
}

// length returns the length of the payload of this element.
pub fn (el Element) length() int {
	p := el.payload() or { return 0 }
	return p.len
}

// encode serializes this element into bytes arrays with default context
pub fn (el Element) encode() ![]u8 {
	ctx := Context{}
	mut dst := []u8{}
	el.encode_with_context(mut dst, ctx)!
	return dst
}

// encode_with_context serializes this el Element into bytes and appended to `dst`.
// Its accepts optional ctx Context.
fn (el Element) encode_with_context(mut dst []u8, ctx Context) ! {
	// we currently only support .der or (stricter) .ber
	if ctx.rule != .der && ctx.rule != .ber {
		return error('Element: unsupported rule')
	}
	// serialize the tag
	el.tag().encode_with_context(mut dst, ctx)!
	// calculates the length of element,  and serialize this length
	payload := el.payload()!
	length := Length.from_i64(payload.len)!
	length.encode_with_context(mut dst, ctx)!
	// append the element payload to destionation
	dst << payload
}

pub fn (el Element) element_size() !int {
	ctx := Context{}
	return el.element_size_with_context(ctx)!
}

// element_size_with_context informs us the length of bytes when this element serialized into bytes.
// Different context maybe produces different result.
fn (el Element) element_size_with_context(ctx Context) !int {
	mut n := 0
	n += el.tag().tag_size()
	length := Length.from_i64(el.payload()!.len)!
	n += length.length_size_with_context(ctx)!
	n += el.payload()!.len

	return n
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
	$if T !is Element {
		return error('Not holding element')
	}
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

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

pub fn encode(el Element) ![]u8 {
	return encode_with_options(el, '')!
}

pub fn encode_with_options(el Element, opt string) ![]u8 {
	mut out := []u8{}
	el.encode_with_options(mut out, opt)!
	return out
}

// encode serializes this element into bytes arrays with default context
pub fn (el Element) encode() ![]u8 {
	mut dst := []u8{}
	el.encode_with_options(mut dst, '')!
	return dst
}

// length returns the length of the payload of this element.
fn (el Element) length() int {
	p := el.payload() or { return 0 }
	return p.len
}

fn (el Element) element_size() !int {
	ctx := default_params()
	return el.element_size_with_context(ctx)!
}

// element_size_with_context informs us the length of bytes when this element serialized into bytes.
// Different context maybe produces different result.
fn (el Element) element_size_with_context(ctx Params) !int {
	mut n := 0
	n += el.tag().tag_size()
	length := Length.from_i64(el.payload()!.len)!
	n += length.length_size_with_rule(ctx.rule)!
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

fn (el Element) encode_with_options(mut out []u8, opt string) ! {
	ctx := default_params()
	el.encode_with_options_context(mut out, opt, ctx)!
}

fn (el Element) encode_with_options_context(mut out []u8, opt string, ctx Params) ! {
	// treated as without option when nil
	if opt.len == 0 {
		el.encode_with_context(mut out, ctx)!
		return
	}
	fo := parse_string_option(opt)!
	fo.validate()!
	// when optional is true, treated differently when present or not
	// in some rules, optional element should not be included in encoding
	if fo.optional {
		if !fo.present {
			// not present, do nothing
			return
		}
		// check for other flag
		if fo.cls != '' {
			if fo.tagnum <= 0 {
				return error('provides with the correct tagnum')
			}
			class := el.tag().tag_class().str().to_lower()
			if class != fo.cls {
				cls := TagClass.from_string(fo.cls)!
				match fo.mode {
					'explicit' {
						wrapped := el.wrap_with_context(cls, fo.tagnum, .explicit, ctx)!
						wrapped.encode_with_context(mut out, ctx)!
					}
					'implicit' {
						wrapped := el.wrap_with_context(cls, fo.tagnum, .implicit, ctx)!
						wrapped.encode_with_context(mut out, ctx)!
					}
					else {}
				} // endof match
			}
			// endof opt.cls != cls
		}
	} else {
		// not an optional
		if fo.cls != '' {
			if fo.tagnum <= 0 {
				return error('provides with correct tagnum')
			}
			cls := TagClass.from_string(fo.cls)!
			if fo.mode != '' {
				mode := TaggedMode.from_string(fo.mode)!
				wrapped := el.wrap_with_context(cls, fo.tagnum, mode, ctx)!
				wrapped.encode_with_context(mut out, ctx)!
			} else {
				// otherwise treat with .explicit
				wrapped := el.wrap_with_context(cls, fo.tagnum, .explicit, ctx)!
				wrapped.encode_with_context(mut out, ctx)!
			}
		}
	}
}

// encode_with_context serializes this el Element into bytes and appended to `dst`.
// Its accepts optional ctx Params.
fn (el Element) encode_with_context(mut dst []u8, ctx Params) ! {
	// we currently only support .der or (stricter) .ber
	if ctx.rule != .der && ctx.rule != .ber {
		return error('Element: unsupported rule')
	}
	// serialize the tag
	el.tag().encode_with_rule(mut dst, ctx.rule)!
	// calculates the length of element,  and serialize this length
	payload := el.payload()!
	length := Length.from_i64(payload.len)!
	length.encode_with_rule(mut dst, ctx.rule)!
	// append the element payload to destionation
	dst << payload
}

fn (el Element) wrap(cls TagClass, num int, mode TaggedMode) !Element {
	ctx := default_params()
	return el.wrap_with_context(cls, num, mode, ctx)!
}

fn (el Element) wrap_with_context(cls TagClass, num int, mode TaggedMode, ctx Params) !Element {
	if cls == .universal {
		return error('no need to wrap into universal class')
	}
	// error when in the same class
	if el.tag().tag_class() == cls {
		return error('no need to wrap into same class')
	}
	newtag := Tag.new(cls, true, num)!
	mut new_element := Asn1Element{
		tag: newtag
	}
	mut payload := []u8{}
	match mode {
		.explicit {
			// explicit add the new tag to serialized element
			el.encode_with_context(mut payload, ctx)!
			new_element.payload = payload
		}
		.implicit {
			// implicit replaces the el tag with the new one
			newpayload := el.payload()!
			new_element.payload = newpayload
		}
	}
	return new_element
}

struct ContextElement {
	// implicitly the class == .context_specific with constructed bit set
	Asn1Element // inner element
	mode TaggedMode
	// outer tag number
	num int
}

struct ApplicationElement {
	Asn1Element
}

struct PrivateELement {
	Asn1Element
}

struct Asn1Element {
mut:
	tag     Tag
	payload []u8
}

fn (ae Asn1Element) tag() Tag {
	return ae.tag
}

fn (ae Asn1Element) payload() ![]u8 {
	return ae.payload
}

fn (ae Asn1Element) encode(mut dst []u8) ! {
	return error('not implemented')
}

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

// encode serializes element into bytes array. By default, its encode in .der rule with empty options.
// See  `encode_with_options` if you want pass an option string. See `field.v` for more option in detail.
pub fn encode(el Element) ![]u8 {
	return encode_with_options(el, '')!
}

// encode_with_options serializes element into bytes array with options string passed to drive the result.
pub fn encode_with_options(el Element, opt string) ![]u8 {
	return el.encode_with_string_options(opt, .der)!
}

fn encode_with_field_options(el Element, fo &FieldOptions) ![]u8 {
	return el.encode_with_field_options(fo, .der)
}

// encode_with_rule encodes element into bytes with encoding rule
fn encode_with_rule(el Element, rule EncodingRule) ![]u8 {
	if rule != .der && rule != .ber {
		return error('Element: unsupported rule')
	}
	mut dst := []u8{}
	el.tag().encode_with_rule(mut dst, rule)!
	// calculates the length of element,  and serialize this length
	payload := el.payload()!
	length := Length.from_i64(payload.len)!
	length.encode_with_rule(mut dst, rule)!
	// append the element payload to destination
	dst << payload

	return dst
}

fn (el Element) encode_with_string_options(opt string, rule EncodingRule) ![]u8 {
	// treated as without option when nil
	if opt.len == 0 {
		out := encode_with_rule(el, rule)!
		return out
	}
	fo := parse_string_option(opt)!
	out := el.encode_with_field_options(fo, rule)!
	return out
}

fn (el Element) encode_with_field_options(fo &FieldOptions, rule EncodingRule) ![]u8 {
	if rule != .der && rule != .ber {
		return error('unsupported rule')
	}
	// treated as without option when nil
	if fo == unsafe { nil } {
		out := encode_with_rule(el, rule)!
		return out
	}
	fo.validate()!
	// when optional is true, treated differently when present or not
	// in some rules, optional element should not be included in encoding
	if fo.optional {
		if !fo.present {
			// not present, return empty
			return []u8{}
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
						wrapped := el.wrap_with_rule(cls, fo.tagnum, .explicit, rule)!
						out := encode_with_rule(wrapped, rule)!
						return out
					}
					'implicit' {
						wrapped := el.wrap_with_rule(cls, fo.tagnum, .implicit, rule)!
						out := encode_with_rule(wrapped, rule)!
						return out
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
				wrapped := el.wrap_with_rule(cls, fo.tagnum, mode, rule)!
				out := encode_with_rule(wrapped, rule)!
				return out
			} else {
				// otherwise treat with .explicit
				wrapped := el.wrap_with_rule(cls, fo.tagnum, .explicit, rule)!
				out := encode_with_rule(wrapped, rule)!
				return out
			}
		}
	}
}

// wrap only universal class, and other class that has primitive form
fn (el Element) wrap(cls TagClass, num int, mode TaggedMode) !Element {
	return el.wrap_with_rule(cls, num, mode, .der)!
}

// we prohibit dan defines some rules when its happen and  returns an error instead
// 1. wrapping into .universal class is not allowed
// 2. wrapping with the same class is not allowed too
// 3. wrapping non-universal class element is not allowed (maybe removed on futures.)
fn (el Element) wrap_with_rule(cls TagClass, num int, mode TaggedMode, rule EncodingRule) !Element {
	if cls == .universal {
		return error('no need to wrap into universal class')
	}
	// error when in the same class
	if el.tag().tag_class() == cls {
		return error('no need to wrap into same class')
	}
	// we dont allow .application, .context_specific, .and private to be wrapped
	el_cls := el.tag().tag_class()
	if el_cls == .application || el_cls == .context_specific || el_cls == .private {
		return error('No need to wrap non-universal class')
	}
	newtag := Tag.new(cls, true, num)!
	mut new_element := RawElement{
		tag: newtag
	}
	match mode {
		.explicit {
			// explicit add the new tag to serialized element
			newpayload := encode_with_rule(el, rule)!
			new_element.payload = newpayload
		}
		.implicit {
			// implicit replaces the el tag with the new one
			payload := el.payload()!
			new_element.payload = payload
		}
	}
	return new_element
}

fn build_payload[T](val T) ![]u8 {
	mut out := []u8{}
	$for field in val.fields {
		// only serialiaze field that implement interfaces
		$if field.typ is Element {
			// if there attributes option
			if field.attrs.len != 0 {
				fo := parse_attrs_to_field_options(field.attrs)!
				current := encode_with_field_options(val.$(field.name), fo)!
				out << current
			} else {
				// without  option
				current := encode(val.$(field.name))!
				out << current
			}
		}
	}
	return out
}

// length returns the length of the payload of this element.
fn (el Element) length() int {
	p := el.payload() or { return 0 }
	return p.len
}

fn (el Element) element_size() !int {
	return el.element_size_with_rule(.der)!
}

// element_size_with_rule informs us the length of bytes when this element serialized into bytes.
// Different rule maybe produces different result.
fn (el Element) element_size_with_rule(rule EncodingRule) !int {
	mut n := 0
	n += el.tag().tag_size()
	length := Length.from_i64(el.payload()!.len)!
	n += length.length_size_with_rule(rule)!
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

/*
fn Element.decode(src []u8) !(Element, i64) {
	ctx := default_params()
	el, pos := Element.decode_with_context(src, 0, ctx)!
	return el, pos
}

// decode deserializes back bytes in src from offet `loc` into Element.
// Basically, its tries to parse a Universal class Element when it is possible.
// Other class parsed as a RawElement.
fn Element.decode_with_context(src []u8, loc i64, ctx &Params) !(Element, i64) {
	raw, next := RawElement.decode_with_context(src, loc, ctx)!
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
	a := el.payload() or { return false }
	b := other.payload() or { return false }
	return el.tag() == other.tag() && a == b
}

fn (el Element) as_raw_element(ctx &Params) !RawElement {
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
fn ElementList.from_bytes(src []u8, ctx &Params) ![]Element {
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
fn (els []Element) hold_different_tag() bool {
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
fn (els []Element) contains(el Element) bool {
	for e in els {
		if !el.equal_with(el) {
			return false
		}
	}
	return true
}


*/

// decode_single decodes single element from bytes, its not allowing trailing data
fn decode_single(src []u8) !Element {
	return decode_single_with_option(src, '')
}

// decode_single decodes single element from bytes with options support, its not allowing trailing data
fn decode_single_with_option(src []u8, opt string) !Element {
	return error('not implemented')
}

@[noinit]
struct BaseElement {
	constructed bool
	num         int
	content     []u8
}

@[noinit]
struct Asn1Element {
	cls         TagClass
	constructed bool
	num         int
	content     []u8
}

fn (a Asn1Element) tag() Tag {
	tag := Tag.new(a.cls, a.constructed, a.num) or { panic('bad tag number of asn1 element') }
	return tag
}

fn (a Asn1Element) payload() ![]u8 {
	return a.content
}

@[noinit]
struct ContextElement {
	inner Asn1Element // inner element
	cls   TagClass = .context_specific
	num   int
mut:
	mode TaggedMode
}

@[noinit]
struct ApplicationElement {
	BaseElement
	cls TagClass = .application
}

fn (app ApplicationElement) tag() Tag {
	tag := Tag.new(app.cls, app.constructed, app.num) or { panic(err) }
	return tag
}

fn (app ApplicationElement) payload() ![]u8 {
	return app.content
}

@[noinit]
struct PrivateELement {
	BaseElement
	cls TagClass = .private
}

fn (prv PrivateELement) tag() Tag {
	tag := Tag.new(prv.cls, prv.constructed, prv.num) or { panic(err) }
	return tag
}

fn (prv PrivateELement) payload() ![]u8 {
	return prv.content
}

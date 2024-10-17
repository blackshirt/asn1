// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// for bytes compare
import crypto.internal.subtle { constant_time_compare }

// This file contains structures and routines for handling ASN.1 Element.
// Its includes:
// 	- basic Element interface, for support ASN.1 element in more generic way
//	- arrays of Element in the form of ElementList
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

// `encode` serializes element into bytes array. By default, its encode in .der rule with empty options.
// See  `encode_with_options` if you want pass an option string. See `field.v` for more option in detail.
pub fn encode(el Element) ![]u8 {
	return encode_with_options(el, '')!
}

// `encode_with_options` serializes element into bytes array with options string passed to drive the result.
pub fn encode_with_options(el Element, opt string) ![]u8 {
	return el.encode_with_string_options(opt, .der)!
}

// `encode_with_field_options` serializes this element into bytes array with options defined in fo.
pub fn encode_with_field_options(el Element, fo FieldOptions) ![]u8 {
	return el.encode_with_field_options(fo, .der)
}

fn (el Element) encode_with_string_options(opt string, rule EncodingRule) ![]u8 {
	// treated as without option when nil
	if opt.len == 0 {
		out := encode_with_rule(el, rule)!
		return out
	}
	fo := FieldOptions.from_string(opt)!
	out := el.encode_with_field_options(fo, rule)!
	return out
}

fn (el Element) encode_with_field_options(fo FieldOptions, rule EncodingRule) ![]u8 {
	if rule != .der && rule != .ber {
		return error('unsupported rule')
	}

	new_element := el.apply_field_options(fo)!
	out := encode_with_rule(new_element, rule)!
	return out
}

// encode_with_rule encodes element into bytes with encoding rule
fn encode_with_rule(el Element, rule EncodingRule) ![]u8 {
	if rule != .der && rule != .ber {
		return error('Element: unsupported rule')
	}
	mut dst := []u8{}

	// when this element is Optional without presence flag, by default would
	// serialize this element into empty bytes otherwise, would serialize underlying element.
	if el is Optional {
		return el.encode()!
	}
	// otherwise, just serializes as normal
	el.tag().encode_with_rule(mut dst, rule)!
	// calculates the length of element,  and serialize this length
	payload := el.payload()!
	length := Length.new(payload.len)!
	length.encode_with_rule(mut dst, rule)!
	// append the element payload to destination
	dst << payload

	return dst
}

// from_object[T] transforms and creates a new Element from generic type (maybe universal type, like an OctetString).
// Its accepts generic element t that you should pass to this function. You should make sure if this element implements
// required methods of the Element, or an error would be returned.
// FIXME: its not tested.
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
// NOTE: Not tested.
// Examples:
// ```v
// oc := asn1.OctetString.from_string("xxx")!
// el := Element.from_object[OctetString](oc)!
// ```
// cast back the element into OctetString.
// ```v
// os := el.into_object[OctetString]()!
// ```
// and then treats os as an OctetString.
pub fn (el Element) into_object[T]() !T {
	if el is T {
		return *el
	}
	return error('Element el does not holding T')
}

// length tells the payload length of this element.
pub fn (el Element) length() !int {
	payload := el.payload()!
	return payload.len
}

// UTILITY HELPER FOR ELEMENT
//

// Helper for validates FieldOptions.
//
// validate_field_options validates FieldOptions is a valid option agains current element.
fn (el Element) validate_field_options(fo FieldOptions) ! {
	el.validate_wrapper_part(fo)!
	el.validate_optional_part(fo)!
	el.validate_default_part(fo)!
}

// validate_wrapper_part validates wrapper's part of fields options again element being
// wrapped to meet requirement. Its return error on fail to validate.
fn (el Element) validate_wrapper_part(fo FieldOptions) ! {
	// Validates wrapper part
	// Its discard all check when fo.cls is empty string, its marked as non-wrapped element.
	if fo.cls != '' {
		if !valid_tagclass_name(fo.cls) {
			return error('Get unexpected fo.cls value:${fo.cls}')
		}
		// provides the tag number
		if fo.tagnum <= 0 {
			return error('Get unexpected fo.tagnum: ${fo.tagnum}')
		}
		// wraps into the same class is not allowed
		el_cls := el.tag().tag_class().str().to_lower()
		if el_cls == fo.cls.to_lower() {
			return error('wraps into same class is not allowed')
		}
		// wraps into UNIVERSAL type is not allowed
		if fo.cls == 'universal' {
			return error('wraps into universal class is not allowed')
		}
		// provides wrap mode, ie, explicit or implicit
		if fo.mode == '' {
			return error('You have not provides mode')
		}
		if !valid_mode_value(fo.mode) {
			return error('Get unexpected mode value:${fo.mode}')
		}
		// when wrapped, you should provide inner tag value.
		if fo.inner == '' {
			return error('You have not provides mode')
		}
		// Provides with correct inner value
		if !is_valid_inner_value(fo.inner) {
			return error('Get unexpected fo.inner value:${fo.inner}')
		}
	}
}

// validate_default_part validates has_default part of field options
fn (el Element) validate_default_part(fo FieldOptions) ! {
	// Validates default part
	if fo.has_default {
		if fo.default_value == none {
			return error('has_default withoud default value')
		}
		def := fo.default_value or { return err }
		if !el.tag().equal(def.tag()) {
			return error('You provides different tag of default_value with  tag of current element')
		}
	}
}

fn (el Element) validate_optional_part(fo FieldOptions) ! {
	// Validates Optional part
	// If the element is already optional, you cant make it optional again by setting optional=true
	if fo.optional {
		if el is Optional {
			return error('You cant mark Optional element as nested Optional')
		}
	}
}

// Helper for wrapping element
//
// apply_wrappers_options turns this element into another element by wrapping it
// with the some options defined in FieldOptions.
fn (el Element) apply_wrappers_options(fo FieldOptions) !Element {
	// no wraps, and discard other wrapper options
	if fo.cls == '' {
		return el
	}
	el.validate_wrapper_part(fo)!
	if fo.has_default {
		el.validate_default_part(fo)!
	}

	cls := TagClass.from_string(fo.cls)!
	mode := TaggedMode.from_string(fo.mode)!

	new_el := el.wrap(cls, fo.tagnum, mode)!

	return new_el
}

// Helper for turns the element into Optional.
//
// apply_optional_options turns this element into another element with OPTIONAL semantic.
fn (el Element) apply_optional_options(fo FieldOptions) !Element {
	// not an optional element, just return the current element.
	if !fo.optional {
		return el
	}
	el.validate_optional_part(fo)!
	if fo.optional && fo.present {
		return el.into_optional_to_present()!
	}
	return el.into_optional()!
}

// into_optional turns this element into Optional.
fn (el Element) into_optional() !Element {
	if el is Optional {
		return error('already optional element')
	}
	opt := Optional.new(el)!
	return opt
}

// into_optional_to_present turns this element into Optional with presences semantic.
fn (el Element) into_optional_to_present() !Element {
	// maybe removed in the future
	if el is Optional {
		return error('already optional element')
	}
	mut opt := Optional.new(el)!
	opt.set_to_present()

	return opt
}

// apply_field_options applies rules in field options into current element
// and turns this into another element.
// by default, optional attribute is more higher precedence over wrapper attribut, ie,
// take the wrap step and then turn into optional (if true)
fn (el Element) apply_field_options(fo FieldOptions) !Element {
	wrapped := el.apply_wrappers_options(fo)!
	// optional options take precedence over wrapper
	// wehen fo.optional is false, new_el is current wrapped element
	new_el := wrapped.apply_optional_options(fo)!
	return new_el
}

fn (el Element) set_default_value(mut fo FieldOptions, value Element) ! {
	// the default tag should match with the current tag
	if el.tag() != value.tag() {
		return error('unmatching tag of default value')
	}
	fo.install_default(value, false)!
	el.validate_default_part(fo)!
}

// wrap only universal class, and other class that has primitive form
fn (el Element) wrap(cls TagClass, num int, mode TaggedMode) !Element {
	return el.wrap_with_rule(cls, num, mode, .der)!
}

fn (el Element) unwrap(fo FieldOptions) !Element {
	// unwrap only element with constructed form
	if !el.tag().is_constructed() {
		return error('You cant unwrap non-constructed element')
	}
	el.validate_wrapper_part(fo)!

	// if unwrapping, el.tag() should == fo.inner produced by wrap operation
	return error('Not implemented')
}

// wrap_with_rule wraps universal element into another constructed class.
// we prohibit dan defines some rules when its happen and  returns an error instead
// 1. wrapping into .universal class is not allowed
// 2. wrapping with the same class is not allowed too
// 3. wrapping non-universal class element is not allowed (maybe removed on futures.)
fn (el Element) wrap_with_rule(cls TagClass, tagnum int, mode TaggedMode, rule EncodingRule) !Element {
	// we dont allow optional element to be wrapped
	if el is Optional {
		return error('optional is not allowed to be wrapped')
	}
	// wraps into .universal is not allowed
	if cls == .universal {
		return error('no need to wrap into universal class')
	}

	el_cls := el.tag().tag_class()
	// error when in the same class
	if el_cls == cls {
		return error('no need to wrap into same class')
	}
	// we dont allow other than .universal class to be wrapped
	if el_cls != .universal {
		return error('No need to wrap non-universal class')
	}
	payload := if mode == .explicit { encode_with_rule(el, rule)! } else { el.payload()! }
	match cls {
		.context_specific {
			// should be constructed
			return ContextElement.new(mode, tagnum, el)!
		}
		.application {
			return ApplicationElement.new(true, tagnum, payload)!
		}
		.private {
			return PrivateELement.new(true, tagnum, payload)!
		}
		else {
			return error('class wrapper not allowed')
		}
	}
}

// KeyDefault is map of string (field.name) into Element for element with default semantic.
// its is to be used for building payload of complex structures like sequence.
// see `make_payload` below.
pub type KeyDefault = map[string]Element

// `make_payload` builds bytes of payload for some structures contains field of Elements.
// Consider this examples from RFC 5280 defines schema.
//  ```v
// Certificate  ::=  SEQUENCE  {
//      tbsCertificate       TBSCertificate,
//      signatureAlgorithm   AlgorithmIdentifier,
//      signatureValue       BIT STRING  }
// ```
// where your structure defined as:.
// ```v
// struct Certificate {
// 		tbs_certificate 	TBSCertificate
//		signature_algorithm	AlgorithmIdentifier
// 		signature_value		BitString
// }
// ```
//
// Usually you can do.
//
// ```v
// cert := Certificate.new()!
// payload := asn1.make_payload[Certificate](cert)!
// ```
//
// and then you can use the produced payload.
pub fn make_payload[T](val T, kd KeyDefault) ![]u8 {
	mut out := []u8{}
	$for field in val.fields {
		// only serialiaze field that implement interfaces
		$if field.typ is Element {
			// if there attributes option
			if field.attrs.len != 0 {
				mut fo := FieldOptions.from_attrs(field.attrs)!
				// TODO: add keyDefault support
				if fo.has_default {
					// install default by getting default element from map
					key := field.name
					def_elem := kd[key] or { return error('missing defaul element') }
					fo.install_default(def_elem, false)!
				}
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

// `encoded_len` calculates the size in bytes when the el element was serialized.
pub fn encoded_len(el Element) int {
	return el.encoded_len()
}

// `encoded_len` calculates the length of bytes when this element was serialized.
pub fn (el Element) encoded_len() int {
	return el.encoded_len_with_rule(.der)
}

// encoded_len_with_rule informs us the length of bytes when this element serialized into bytes.
// Different rule maybe produces different result.
fn (el Element) encoded_len_with_rule(rule EncodingRule) int {
	mut n := 0
	n += el.tag().tag_size()
	payload := el.payload() or { panic(err) }
	length := Length.new(payload.len) or { panic(err) }
	n += length.length_size_with_rule(rule) or { panic(err) }
	n += payload.len

	return n
}

fn (el Element) expect_tag(t Tag) bool {
	return el.tag() == t
}

// equal checks whether this two element equal and holds the same tag and content
pub fn (el Element) equal(other Element) bool {
	return el.equal_tag(other) && el.equal_payload(other)
}

fn (el Element) equal_tag(other Element) bool {
	return el.tag() == other.tag()
}

fn (el Element) equal_payload(other Element) bool {
	// taken from crypto.internal.subtle
	x := el.payload() or { panic(err) }
	y := other.payload() or { panic(err) }

	return constant_time_compare(x, y) == 1
}

fn Element.parse(mut p Parser) !Element {
	el := p.read_tlv()!
	return el
}

fn Element.decode(src []u8) !(Element, i64) {
	el, pos := Element.decode_with_rule(src, 0, .der)!
	return el, pos
}

// decode deserializes back bytes in src from offet `loc` into Element.
// Basically, its tries to parse a Universal class Element when it is possible.
fn Element.decode_with_rule(src []u8, loc i64, rule EncodingRule) !(Element, i64) {
	tag, length_pos := Tag.decode_with_rule(src, loc, rule)!
	length, content_pos := Length.decode_with_rule(src, length_pos, rule)!
	// get the bytes
	bytes := if length == 0 {
		[]u8{}
	} else {
		if content_pos == src.len {
			[]u8{}
		} else {
			unsafe { src[content_pos..content_pos + length] }
		}
	}
	next_pos := content_pos + length
	elem := parse_element(tag, bytes)!

	return elem, next_pos
}

// ElementList.
//
// ElementList is arrays of Element.
// Many places maybe required this wells, likes Sequence or Set fields.
pub type ElementList = []Element

pub fn (els ElementList) payload() ![]u8 {
	return els.payload_with_rule(.der)!
}

fn (els ElementList) payload_with_rule(rule EncodingRule) ![]u8 {
	mut out := []u8{}
	for el in els {
		bytes := encode_with_rule(el, rule)!
		out << bytes
	}
	return out
}

pub fn (els ElementList) encoded_len() int {
	mut n := 0
	for el in els {
		n += el.encoded_len()
	}
	return n
}

// ElementList.from_bytes parses bytes in src as series of Element or return error on fails.
// Its does not support trailing data.
pub fn ElementList.from_bytes(src []u8) ![]Element {
	mut els := []Element{}
	if src.len == 0 {
		// empty list
		return els
	}
	mut i := i64(0)
	for i < src.len {
		el, pos := Element.decode_with_rule(src, i, .der)!
		i = pos
		els << el
	}
	if i > src.len {
		return error('i > src.len')
	}
	if i < src.len {
		return error('The src contains unprocessed bytes')
	}
	return els
}

// decode decodes single element from bytes, its not allowing trailing data
pub fn decode(src []u8) !Element {
	return decode_with_options(src, '')
}

// decode_with_options decodes single element from bytes with options support, its not allowing trailing data.
// Its accepts options string to drive decoding process.
pub fn decode_with_options(bytes []u8, opt string) !Element {
	if opt.len == 0 {
		el, pos := Element.decode(bytes)!
		if pos > bytes.len {
			return error('decode on data with trailing data')
		}
		return el
	}
	fo := FieldOptions.from_string(opt)!
	return decode_with_field_options(bytes, fo)!
}

pub fn decode_with_field_options(bytes []u8, fo FieldOptions) !Element {
	// TODO
	return error('decode_with_field_options not implemented')
}

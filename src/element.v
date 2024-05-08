module asn1

// Element represents a generic ASN.1 Element.
// Most of the standard Universal class element defined on this module
// satisfies this interface. This interface was also expandabled by methods
// defined on this interface.
pub interface Element {
	// tag tells the identity tag of this Element
	tag() Tag
	// payload tells the raw payload (values) of this Element.
	// Its accept Params parameter in p to allow extending
	// behaviour how this raw bytes is produced by implementation.
	// Its depends on tags part how interpretes this payload,
	// whether the tag is in constructed or primitive form.
	payload(p Params) ![]u8
}

// Element.new creates a new Element from RawElement with tag and payload
pub fn Element.new(tag Tag, payload []u8) !Element {
	return RawElement{
		tag: tag
		payload: payload
	}
}

// FIXME: its not tested
// from_object creates a new element from raw type (maybe universal type, like OctetString)
// examples:
// ```v
// oc := asn1.OctetString.from_string("xxx")!
// el := Element.from_object[OctetString](oc)!
// ```
// and then treats your OctetString as an Element
pub fn Element.from_object[T](t T) !Element {
	return t
}

// length returns the length of the payload of this element.
pub fn (e Element) length(p Params) !int {
	payload := e.payload(p)!
	return payload.len
}

// encode serializes this e Element into bytes and appended to `dst`.
// Its accepts optional p Params.
pub fn (e Element) encode(mut dst []u8, p Params) ! {
	e.tag().encode(mut dst, p)!
	payload := e.payload(p)!
	length := Length.from_i64(payload.len)!
	length.encode(mut dst, p)!
	dst << payload
}

// packed_length informs us the length of how many bytes when this e Element
// was serialized into bytes.
pub fn (e Element) packed_length(p Params) !int {
	mut n := 0
	n += e.tag().packed_length(p)!
	payload := e.payload(p)!
	length := Length.from_i64(payload.len)!
	n += length.packed_length(p)!
	n += payload.len

	return n
}

// decode deserializes back bytes in src from offet loc into Element.
// Basically, its tries to parse a Universal class Elememt when it is possible.
// Other class parsed as a RawElement.
pub fn Element.decode(src []u8, loc i64, p Params) !(Element, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	bytes := raw.payload

	match raw.tag.class() {
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

pub fn (e Element) expect_tag(t Tag) bool {
	return e.tag() == t
}

// equal_with checks whether this two element equal and holds the same tag and content
pub fn (e Element) equal_with(other Element) bool {
	a := e.payload() or { panic(err) }
	b := other.payload() or { panic(err) }
	return e.tag() == other.tag() && a == b
}

// ElementList is arrays of ELement
type ElementList = []Element

// ElementList.from_bytes parses bytes in src as series of Element or return error on fails
pub fn ElementList.from_bytes(src []u8, p Params) ![]Element {
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
		if !e.equal_with(el) {
			return false
		}
	}
	return true
}

// Raw ASN.1 Element
pub struct RawElement {
pub mut:
	// the tag of the RawElement
	tag Tag
	// payload is the value of this RawElement, its depend how its would be interpreted.
	// when the tag is primitive, its represents real value of this RawElement.
	// otherwise, if its a constructed, its contains another unparsed RawElement
	payload []u8
}

// RawElement.new creates a new raw ASN.1 Element
pub fn RawElement.new(t Tag, payload []u8) RawElement {
	el := RawElement{
		tag: t
		payload: payload
	}
	return el
}

// tag returns the tag of the RawElement
pub fn (el RawElement) tag() Tag {
	return el.tag
}

pub fn (el RawElement) length(p Params) !int {
	return el.payload.len
}

// payload is payload of this RawElement
pub fn (el RawElement) payload(p Params) ![]u8 {
	return el.payload
}

pub fn (e RawElement) packed_length(p Params) !int {
	mut n := 0
	n += e.tag.packed_length(p)!
	length := Length.from_i64(e.payload.len)!
	n += length.packed_length(p)!
	n += e.payload.len

	return n
}

pub fn (e RawElement) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('RawElement: unsupported mode')
	}
	e.tag.encode(mut dst, p)!
	length := Length.from_i64(e.payload.len)!
	length.encode(mut dst, p)!
	dst << e.payload
}

pub fn RawElement.decode(src []u8, loc i64, p Params) !(RawElement, i64) {
	// minimal length bytes contains tag and the length is two bytes
	if src.len < 2 {
		return error('RawElement: bytes underflow')
	}
	// guard check
	if p.mode != .der && p.mode != .ber {
		return error('RawElement: bad mode')
	}
	mut raw := RawElement{}
	tag, pos := Tag.decode(src, loc, p)!
	raw.tag = tag
	// check if the offset position is not overflowing src.len
	if pos >= src.len {
		return error('RawElement: pos overflow')
	}
	// read the length part
	len, idx := Length.decode(src, pos, p)!
	// check if len == 0, its mean this parsed element has no content bytes
	// on last offset
	if len == 0 {
		raw.payload = []u8{}
	} else {
		// len !=0
		// check if idx + len is not overflow src.len, if its not happen,
		// this element has a content, or return error if not.
		// when idx == src.len, but len != 0, its mean the input is truncated
		// its also same mean for idx+len is over to the src.len
		if idx >= src.len || idx + len > src.len {
			return error('RawElement: truncated src bytes')
		}
		payload := unsafe { src[idx..idx + len] }
		if len != payload.len {
			return error('RawElement: unmatching length')
		}
		raw.payload = payload
	}
	return raw, idx + len
}

// as_tagged treats and parse the RawElement r as TaggedType element with inner_tag is
// an expected tag of inner Element being tagged.
pub fn (r RawElement) as_tagged(mode TaggedMode, inner_tag Tag, p Params) !TaggedType {
	// make sure the tag is in constructed form, when it true, the r.payload is an ASN.1 Element
	// when mode is explicit or the r.payload is bytes content by itself when mode is implicit.
	if r.tag.is_constructed() {
		if r.payload.len == 0 {
			return error('tag is constructed but no payload')
		}
		if mode == .explicit {
			raw, _ := RawElement.decode(r.payload, 0, p)!
			if raw.tag != inner_tag {
				return error('expected inner_tag != parsed tag')
			}

			if raw.payload.len == 0 {
				// empty sub payload
				inner := RawElement{
					tag: raw.tag
					payload: raw.payload
				}
				tt := TaggedType{
					outer_tag: r.tag
					mode: .explicit
					inner_el: inner
				}
				return tt
			}
			// otherwise are ok
			sub := raw.payload

			// if tag is constructed, its maybe recursive thing
			inner_el := if raw.tag.is_constructed() {
				parse_constructed_element(raw.tag, sub)!
			} else {
				// otherwise its a primitive type
				parse_primitive_element(raw.tag, sub)!
			}
			tt := TaggedType{
				outer_tag: r.tag
				mode: .explicit
				inner_el: inner_el
			}
			return tt
		}
		// as in implicit mode, r.payload is a contents payload by itself
		// TODO: should we can treat r.payload as ASN1 element when inner_tag is constructed
		// FIXME:
		// otherwise, its just RawElement
		inner_el := RawElement.new(inner_tag, r.payload)
		tt := TaggedType{
			outer_tag: r.tag
			mode: .implicit
			inner_el: inner_el
		}
		return tt
	}
	return error('This RawElement can not be treated as TaggedType')
}

// ANY DEFINED BY
//
// Note: not tested
// AnyDefinedBy is not implements `asn1.Element`, so its can't be used as an ASN.1 ELement.
pub struct AnyDefinedBy {
	// params is raw bytes contents, its maybe contains only payload element
	// or encoded element, or just null bytes
	params []u8
}

// from_element creates AnyDefinedBy from ASN.1 Element el. Its stores
// encoded element as AnyDefinedBy's content.
pub fn AnyDefinedBy.from_element(el Element, p Params) !AnyDefinedBy {
	mut out := []u8{}
	el.encode(mut out, p)!
	return AnyDefinedBy{
		params: out
	}
}

// from_bytes creates AnyDefinedBy from raw bytes in b in uninterpreted way.
pub fn AnyDefinedBy.from_bytes(b []u8) AnyDefinedBy {
	return AnyDefinedBy{
		params: b
	}
}

// as_element interpretes this AnyDefinedBy params as an ASN.1 Element
pub fn (a AnyDefinedBy) as_element(p Params) !Element {
	el, pos := Element.decode(a.params, 0, p)!
	if pos != a.params.len {
		return error('AnyDefinedBy params contains unprocessed bytes')
	}
	return el
}

// as_raw returns AnyDefinedBy as raw bytes
pub fn (a AnyDefinedBy) as_raw() []u8 {
	return a.params
}

// AnyDefinedBy.decode parses and decodes bytes in src into AnyDefinedBy.
// Its try to interprete the bytes as an encoded ASN.1 Element
pub fn AnyDefinedBy.decode(src []u8, loc i64, p Params) !(AnyDefinedBy, i64) {
	el, pos := Element.decode(src, loc, p)!
	ret := AnyDefinedBy.from_element(el, p)!
	return ret, pos
}

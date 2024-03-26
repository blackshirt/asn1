module asn1

// ASN.1 Element
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
pub fn (e Element) length(p Params) int {
	payload := e.payload(p) or { panic(err) }
	return payload.len
}

// encode serializes this Element e into bytes and appended to `dst`.
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
pub fn (e Element) packed_length(p Params) int {
	mut n := 0
	n += e.tag().packed_length(p)
	payload := e.payload(p) or { panic(err) }
	length := Length.from_i64(payload.len) or { panic(err) }
	n += length.packed_length(p)
	n += payload.len

	return n
}

// unpack_from_asn1 deserializes bytes in src from offet loc into Element.
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

// equal checks whether this two element equal and holds the same tag and content
pub fn (e Element) equal(other Element) bool {
	a := e.payload() or { panic(err) }
	b := other.payload() or { panic(err) }
	return e.tag() == other.tag() && a == b
}

type ElementList = []Element

// ElementList.from_bytes parses bytes in src as series of Element.
// from_bytes parses bytes in src to array of Element or return error on fail
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
		if !e.equal(el) {
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

pub fn (el RawElement) tag() Tag {
	return el.tag
}

pub fn (el RawElement) length(p Params) int {
	return el.payload.len
}

// payload is payload of this RawElement
pub fn (el RawElement) payload(p Params) ![]u8 {
	return el.payload
}

pub fn (e RawElement) packed_length(p Params) int {
	mut n := 0
	n += e.tag.packed_length(p)
	length := Length.from_i64(e.payload.len) or { panic(err) }
	n += length.packed_length(p)
	n += e.payload.len

	return n
}

pub fn (e RawElement) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('RawElement: unsupported mode')
	}
	e.tag.encode(mut dst, p)!
	length := Length.from_i64(e.payload.len) or { panic(err) }
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

// OPTIONAL
// Optional has no dedicated tag, its follow some already defined element
pub struct Optional {
	elm Element
}

pub fn Optional.new(el Element) Optional {
	return Optional{el}
}

pub fn (op Optional) tag() Tag {
	return op.elm.tag()
}

pub fn (op Optional) payload(p Params) ![]u8 {
	return op.elm.payload(p)
}

pub fn (op Optional) length(p Params) int {
	return op.elm.length(p)
}

pub fn (op Optional) encode(mut dst []u8, p Params) ! {
	op.elm.encode(mut dst, p)!
}

pub fn Optional.decode(src []u8, loc i64, p Params) !(Optional, i64) {
	el, pos := Element.decode(src, loc, p)!
	ret := Optional{el}
	return ret, pos
}

// present checks whether this Optional o present with expected tag t.
pub fn (o Optional) present(t Tag) bool {
	return o.elm.tag() == t
}

// CHOICE
// Choice element also no have dedicated semantic and tag.
// Its also follow underlying choosen element
pub struct Choice {
	choices []Element
mut:
	// choosen element
	choosen Element
}

pub fn Choice.new(choices []Element, el Element) !Choice {
	if !choices.contains(el) {
		return error('Choice: el is not in choices')
	}
	ret := Choice{
		choices: choices
		choosen: el
	}
	return ret
}

pub fn (c Choice) tag() Tag {
	return c.choosen.tag()
}

pub fn (c Choice) payload(p Params) ![]u8 {
	return c.choosen.payload(p)
}

pub fn (c Choice) length(p Params) int {
	return c.choosen.length(p)
}

pub fn (c Choice) encode(mut dst []u8, p Params) ! {
	c.choosen.encode(mut dst, p)!
}

pub fn Choice.decode(choices []Element, src []u8, loc i64, p Params) !(Choice, i64) {
	el, pos := Element.decode(src, loc, p)!
	ret := Choice.new(choices, el)!
	return ret, pos
}

pub struct AnyDefinedBy {
	by Element
}

pub fn AnyDefinedBy.new(el Element) AnyDefinedBy {
	return AnyDefinedBy{el}
}

pub fn (a AnyDefinedBy) tag() Tag {
	return a.by.tag()
}

pub fn (a AnyDefinedBy) payload(p Params) ![]u8 {
	return a.by.payload(p)
}

pub fn (a AnyDefinedBy) length(p Params) int {
	return a.by.length(p)
}

pub fn (a AnyDefinedBy) encode(mut dst []u8, p Params) ! {
	a.by.encode(mut dst, p)!
}

pub fn AnyDefinedBy.decode(src []u8, loc i64, p Params) !(AnyDefinedBy, i64) {
	el, pos := Element.decode(src, loc, p)!
	ret := AnyDefinedBy{el}
	return ret, pos
}

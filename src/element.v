module asn1

// ASN.1 Element
pub interface Element {
	// tag tells the tag of this Element
	tag() Tag
	// length tells the length of this Element, how many bytes the payload is.
	// This length should match with the `Element.payload()` lenght
	length(p Params) int
	// payload tells the raw payload (values) of this Element.
	// Its accept Params parameter in p to allow extending
	// behaviour how this raw bytes is produced by implemntation.
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

// pack_to_asn1 serializes this Element e to bytes and appended to `out`.
// Its accepts optional p Params.
pub fn (e Element) pack_to_asn1(mut out []u8, p Params) ! {
	e.tag().pack_to_asn1(mut out, p)!
	payload := e.payload(p)!
	len := e.length(p)
	if payload.len != len {
		return error('Element: unmatching length')
	}
	length := Length.from_i64(len)!
	length.pack_to_asn1(mut out, p)!
	out << payload
}

// packed_length informs us the length of how many bytes when this e Element
// was serialized to bytes.
pub fn (e Element) packed_length(p Params) int {
	mut n := 0
	n += e.tag().packed_length(p)
	length := Length.from_i64(e.length()) or { panic(err) }
	n += length.packed_length(p)
	n += length

	return n
}

// unpack_from_asn1 deserializes bytes in src from offet loc into Element.
pub fn Element.unpack_from_asn1(src []u8, loc i64, p Params) !(Element, i64) {
	if src.len < 2 {
		return error('Element: bad length bytes')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Element: unsupported mode')
	}
	if loc > src.len {
		return error('Element: bad position offset')
	}
	// TODO: still no check, add check
	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	if idx > src.len || idx + len > src.len {
		return error('Element: truncated input')
	}
	bytes := unsafe { src[idx..idx + len] }

	match tag.class() {
		.universal {
			if tag.is_constructed() {
				return parse_constructed_element(tag, bytes)!, idx + len
			}

			return parse_primitive_element(tag, bytes)!, idx + len
		}
		.application {
			return RawElement.new(tag, bytes), idx + len
		}
		.context_specific {
			r := RawElement.new(tag, bytes)
			if tag.is_constructed() {
				inn_tag, _ := Tag.unpack_from_asn1(bytes, 0, p)!
				tt := r.as_tagged(.explicit, inn_tag, p)!
				return tt, idx + len
			}
			return r, idx + len
		}
		.private {
			return RawElement.new(tag, bytes), idx + len
		}
	}
}

type ElementList = []Element

// ElementList.from_bytes parses bytes in src as series of Element.
// from_bytes parses bytes in src to array of Element or return error on fail
pub fn ElementList.from_bytes(src []u8) ![]Element {
	mut els := []Element{}
	if src.len == 0 {
		// empty list
		return els
	}
	mut i := i64(0)
	for i < src.len {
		el, pos := Element.unpack_from_asn1(src, i)!
		els << el
		i += pos
	}
	if i > src.len {
		return error('i > src.len')
	}
	if i < src.len {
		return error('contains unprocessed bytes')
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

// Raw ASN.1 Element
pub struct RawElement {
	// the tag of the RawElement
	tag Tag
	// payload is the value of this RawElement, its depend how its would be interpreted.
	// when the tag is primitive, its represents real value of this RawElement.
	// otherwise, if its a constructed, its contains another unparsed RawElement
	payload []u8
}

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

pub fn (el RawElement) payload(p Params) ![]u8 {
	return el.payload
}

pub fn (e RawElement) packed_length(p Params) int {
	mut n := 0
	n += e.tag.packed_length(p)
	length := Length.from_i64(e.length(p)) or { panic(err) }
	n += length.packed_length(p)
	n += e.payload.len

	return n
}

pub fn (e RawElement) pack_to_asn1(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('RawElement: unsupported mode')
	}
	e.tag.pack_to_asn1(mut dst, p)!
	length := Length.from_i64(e.payload.len) or { panic(err) }
	length.pack_to_asn1(mut dst, p)!
	dst << e.payload
}

pub fn RawElement.unpack_from_asn1(src []u8, loc i64, p Params) !(RawElement, i64) {
	if src.len < 2 {
		return error('RawElement: bytes underflow')
	}
	if p.mode != .der && p.mode != .ber {
		return error('RawElement: unsupported mode')
	}
	// todo : validate element
	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// no contents
	if len == 0 {
		el := RawElement{
			tag: tag
			payload: []u8{}
		}
		return el, idx
	}
	if idx > src.len || idx + len > src.len {
		return error('RawElement: truncated bytes contents')
	}
	// TODO: check the length, its safe to access bytes
	bytes := unsafe { src[idx..idx + len] }

	if len != bytes.len {
		return error('RawElement: unmatching length')
	}
	el := RawElement{
		tag: tag
		payload: bytes
	}
	return el, idx + len
}

// as_tagged treats and parse the RawElement r as TaggedType element with inner_tag is
// an expected tag of inner Element being tagged.
pub fn (r RawElement) as_tagged(mode TaggedMode, inner_tag Tag, p Params) !TaggedType {
	// make sure tag is in constructed form, when it true, the r.payload is an ASN.1 Element
	// when mode is explicit or the r.payload is bytes content by itself when mode is implicit.
	if r.tag.is_constructed() {
		if r.payload.len == 0 {
			return error('tag constructed but no payload')
		}
		if mode == .explicit {
			tag, pos := Tag.unpack_from_asn1(r.payload, 0, p)!
			if tag != inner_tag {
				return error('expected inner_tag != parsed tag')
			}
			if pos > r.payload.len {
				return error('bad pos')
			}
			len, idx := Length.unpack_from_asn1(r.payload, pos, p)!
			if idx > r.payload.len || len + idx > r.payload.len {
				return error('truncated input')
			}
			if len == 0 {
				// empty sub payload
				inner := RawElement{
					tag: tag
					payload: []u8{}
				}
				tt := TaggedType{
					outer_tag: r.tag
					mode: .explicit
					inner_el: inner
				}
				return tt
			}
			// otherwise are ok
			sub := unsafe { r.payload[idx..idx + len] }

			// if tag is constructed, its make possible to do
			// recursive thing that we currently dont want support
			// so, return an error instead
			inner_el := if tag.is_constructed() {
				parse_constructed_element(tag, sub)!
			} else {
				// otherwise its a primitive type
				parse_primitive_element(tag, sub)!
			}
			tt := TaggedType{
				outer_tag: r.tag
				mode: .explicit
				inner_el: inner_el
			}
			return tt
		}
		// as implicit mode, r.payload is a contents payload by itself
		// TODO: should we can treat r.payload as ASN1 element when inner_tag is constructed
		if inner_tag.is_constructed() {
			inner_el := parse_constructed_element(inner_tag, r.payload)!
			tt := TaggedType{
				outer_tag: r.tag
				mode: .implicit
				inner_el: inner_el
			}
			return tt
		}
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

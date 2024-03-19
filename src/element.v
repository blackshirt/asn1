module asn1

// ASN.1 Element
interface Element {
	// tag tells the tag of this Element
	tag() Tag
	// payload_length is the length of Element's paylaod, without
	// the tag length and length itself.
	payload_length() int
	// payload tells the raw payload (values) of this Element
	payload() ![]u8
	// packed_length tells total length of serialized Element
	// included tag length and the length itself
	packed_length() int
	// pack_to_asn1 serializes Element to dst
	pack_to_asn1(mut dst []u8, p Params) !
}

fn Element.new(tag Tag, payload []u8) !Element {
	return RawElement{
		tag: tag
		payload: payload
	}
}

fn Element.unpack_from_asn1(src []u8, loc i64, p Params) !(Element, i64) {
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

	return RawElement{
		tag: tag
		payload: bytes
	}, idx + len
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

// Raw ASN.1 Element
struct RawElement {
	// the tag of the RawElement
	tag Tag
	// payload is the value of this RawElement, its depend how its would be interpreted.
	// when the tag is primitive, its represents real value of this RawElement.
	// otherwise, if its a constructed, its contains another unparsed RawElement
	payload []u8
}

fn RawElement.new(t Tag, payload []u8) !RawElement {
	el := RawElement{
		tag: t
		payload: payload
	}
	return el
}

fn (el RawElement) tag() Tag {
	return el.tag
}

fn (el RawElement) payload() ![]u8 {
	return el.payload
}

fn (el RawElement) payload_length() int {
	return el.payload.len
}

fn (e RawElement) packed_length() int {
	mut n := 0
	n += e.tag.packed_length()
	length := Length.from_i64(e.payload.len) or { panic(err) }
	n += length.packed_length()
	n += e.payload.len

	return n
}

fn (e RawElement) pack_to_asn1(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('RawElement: unsupported mode')
	}
	e.tag.pack_to_asn1(mut dst, p)!
	length := Length.from_i64(e.payload.len) or { panic(err) }
	length.pack_to_asn1(mut dst, p)!
	dst << e.payload
}

fn RawElement.unpack_from_asn1(src []u8, loc i64, p Params) !(RawElement, i64) {
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

fn (e RawElement) need_parse_data() bool {
	need := if e.tag.is_constructed() { true } else { false }
	return need
}

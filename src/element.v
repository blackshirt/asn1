module asn1

// raw ASN.1 Element
struct RawElemwnt {
	tag    Tag
	values []u8
}

// generic ASN.1 Element
struct Element[T] {
	// the tag of the Element
	tag    Tag
	// data is the value of this Element, its depend how its would be interpreted.
	// when the tag is primitive, its represents real value of this Element.
	// otherwise, if its a constructed, its contains another unparsed Element
	payload []u8
}

fn Element.new[T](t Tag, payload []u8) !Element[T] {
	el := Element[T]{
		tag: t
		length: Length.from_i64(payload.len)!
		payload: payload
	}
	return el
}

fn (el Element[T]) tag() Tag {
	return el.tag
}

fn (e Element) valid_length() bool {
	return e.length == e.raw_data.len
}

fn (e Element) need_parse_data() bool {
	need := if e.tag.is_constructed() { true } else { false }
	return need
}

fn (e Element) packed_length() int {
	if e.valid_length() {
		mut n := 0
		n += e.tag.packed_length()
		n += e.length.packed_length()
		n += e.raw_data.len

		return n
	}
	// something bad if e.Length != e.raw_data.len
	panic('Should not here')
}

fn (e Element) pack_to_asn1(mut dst []u8, p Params) ! {
	if !e.valid_length() {
		return error('Element: bad Length')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Element: unsupported mode')
	}
	e.tag.pack_to_asn1(mut dst, p)!
	e.length.pack_to_asn1(mut dst, p)!
	dst << e.raw_data
}

fn Element.unpack_from_asn1(src []u8, loc i64, p Params) !(Element, i64) {
	if src.len < 2 {
		return error('Element: bytes underflow')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Element: unsupported mode')
	}
	// todo : validate element
	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// no contents
	if len == 0 {
		el := Element{
			tag: tag
			length: len
			raw_data: []u8{}
		}
		return el, idx
	}
	if idx > src.len || idx + len > src.len {
		return error('Element: truncated bytes contents')
	}
	// TODO: check the length, its safe to access bytes
	bytes := unsafe { src[idx..idx + len] }

	if len != bytes.len {
		return error('Element: unmatching length')
	}
	el := Element{
		tag: tag
		length: len
		raw_data: bytes
	}
	return el, idx + len
}

fn (els []Element) hold_thesame_tag() bool {
	// if empty just true
	if els.len == 0 {
		return true
	}
	tag0 := els[0].tag()
	return els.all(it.tag() == tag0)
}

fn (mut els []Element) add_element(el Element) {}

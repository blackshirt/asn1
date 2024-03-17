module asn1

struct Element {
	// the tag of the Element
	tag Tag
	// the Length should matching with raw_data.len
	length Length
	// data is the value of this Element, its depend how its would be interpreted.
	// when the tag is primitive, its represents real value of this Element.
	// otherwise, if its a constructed, its contains another unparsed Element
	raw_data []u8
}

fn Element.new(t Tag, payload []u8) Element {
	el := Element{
		tag: tag
		length: Length.from_i64(payload.len)!
		raw_data: payload
	}
	return el
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

fn (e Element) pack(mut to []u8, mode EncodingMode, p Params) ! {
	if !e.valid_length() {
		return error('Element: bad Length')
	}
	match mode {
		.der, .ber {
			e.tag.pack_to_asn1(mut to, .der, p)!
			e.length.pack_to_asn1(mut to, .der, p)!
			to << e.raw_data
		}
		else {
			return error('unsupported mode')
		}
	}
}

fn Element.unpack(b []u8, loc i64, mode EncodingMode, p Params) !Element {
	if b.len < 2 {
		return error('Element: bytes underflow')
	}
	match mode {
		.ber, .der {
			tag, pos := Tag.unpack_from_asn1(b, loc, mode, p)!
			len, idx := Length.unpack_from_asn1(b, pos, mode, p)!
			// no contents
			if len == 0 {
				el := Element{
					tag: tag
					length: len
					raw_data: []u8{}
				}
				return el, idx
			}
			if idx > b.len || idx + len > b.len {
				return error('Element: truncated bytes contents')
			}
			// TODO: check the length, its safe to access bytes
			bytes := unsafe { b[idx..idx + len] }

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
		else {
			return error('Unsupported mode')
		}
	}
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

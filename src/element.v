module asn1

// Params is optional params passed to pack or unpacking
// of tag, length or ASN.1 element to drive how encoding works.
@[params]
pub struct Params {}

enum TaggedMode {
	implicit
	explicit
}

// Tagged type element
struct TaggedType {
mut:
	// class of TaggedType element was default to .context_specific
	expected_tag Tag
	mode         TaggedMode = .explicit
	inner_el     Element
}

fn TaggedType.new(tagmode TaggedMode, expected_tag Tag, el Element) !TaggedType {
	// Tagged type should in constructed form
	if !expected_tag.is_compound() {
		return error("TaggedType tag should in constructed form")
	}
	return TaggedType{
		expected_tag: expected_tag
		mode: tagmode
		inner_el: el
	}
}

fn TaggedType.new_explicit(expected_tag Tag, el Element) !TaggedType {
	return TaggedType.new(.explicit, expected_tag, el)
}

fn TaggedType.new_implicit(expected_tag Tag, el Element) !TaggedType {
	return TaggedType.new(.explicit, expected_tag, el)
}

fn (tt TaggedType) packed_length() int {
	mut n := 0
	match tt.mode {
		.explicit {
			// when in explicit mode, outer tag and length is appended to packed inner element
			n += tt.expected_tag.packed_length()
			// inner_length also included length of tag and length of inner Element
			inner_length := tt.inner_el.packed_length()

			tt_length := Length.from_i64(inner_length) or { panic(err) }
			n += tt_length.packed_length()
			n += inner_length

			return n
		}
		.implicit {
			// when in implicit mode, inner tag and length of inner element being replaced by outer tag and length
			n += tt.expected_tag.packed_length()
			// in implicit mode, inner_length only contains inner_el.raw_data.len length (without tag and length)
			inner_length := tt.inner_el.raw_data.len
			tt_length := Length.from_i64(inner_length) or { panic(err) }
			n += tt_length.packed_length()
			n += inner_length

			return n
		}
	}
}

fn (tt TaggedType) pack_to_asn1(mut to []u8, mode EncodingMode, p Params) ! {
	// TaggedType tag should in constructed form
	if !tt.expected_tag.is_compound() {
		return error("TaggedType tag should in constructed form")
	}
	match mode {
		.der {
			match tt.mode {
				.explicit {
					// wraps the inner element with this tag and length
					tt.expected_tag.pack_to_asn1(mut to, .der)!
					length := tt.inner_el.element_length()
					len := Length.from_i64(length)!
					len.pack_to_asn1(mut to, mode)!
					tt.inner_el.pack_to_asn1(mut to, mode)!
				}
				.implicit {
					// replace the tag.of inner element with this tag
					tt.expected_tag.pack_to_asn1(mut to, .der)!
					tt.inner_el.length.pack_to_asn1(mut to, mode)!
					to << tt.inner_el.content
				}
			}
		}
		else {
			return error('unsupported mode')
		}
	}
}

fn TaggedType.unpack_from_asn1(b []u8, loc i64, mode EncodingMode, inner_tag Tag, tm TaggedMode, p Params) !TaggedType {
	if b.len < 2 {
		return error("TaggedType: bytes underflow")
	}
	match mode {
		.ber, .der {
			// external tag 
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, mode, p)!
			// TODO: check the tag, do we need .class == .context_specific
			if !tag.is_compound() {
				return error('TaggedType: tag check failed, not compound')
			}
			len, idx := asn1.Length.unpack_from_asn1(b, pos, mode, p)!
			if len == 0 {
				// its bad TaggedType with len==0, ie, without contents
				return error("TaggedType: len==0")
			}
			if idx > b.len || idx + len > b.len {
				return error('TaggedType: truncated bytes')
			}
			// TODO: check the length, its safe to access bytes
			bytes := unsafe { b[idx..idx + len] }
			mut tt := TaggedType{}
			match tm {
				.explicit {
					// when explicit, unpack element from bytes 
					inner := Element.unpack(bytes, 0, mode, p)!
					if inner.tag != inner_tag {
						return error("unexpected inner tag")
					}
					tt.expected_tag = tag 
					tt.mode = .explicit
					tt.inner_el = inner
				}
				.implicit {
					// when in .implicit mode, inner tag is unknown, so we pass inner_tag as expected tag
					// the bytes is the values of the element 
					inner: Element{
							tag: inner_tag
							length: Length.from_i64(bytes.len)!
							raw_data: bytes 
					}
					tt.expected_tag = tag 
					tt.mode: = .implicit
					tt.inner_el = inner 
				}
			}
			return tt, idx + len
		}
		else {
			return error("Unsupported mode")
		}
	}
}

struct Element {
	tag Tag
	// the Length should matching with raw_data.len
	length Length
	// data is the value of this Element, its depend how its would be interpreted.
	// when the tag is primitive, its represents real value of this Element.
	// otherwise, if its a compound, its contains another unparsed Element
	raw_data []u8
}

fn (e Element) valid_length() bool {
	return e.length == e.raw_data.len
}

fn (e Element) need_parse_data() bool {
	need := if e.tag.is_compound() { true } else { false }
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

// encoding mode
pub enum EncodingMode {
	der = 0
	ber = 1
	oer = 2
	per = 3
	xer = 4
}

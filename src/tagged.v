// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// EXPLICIT and IMPLICIT
//
// rule of context specific wrapping. explicit rule add new tag
// to the existing object, implicit rule replaces tag of original object.
pub enum TaggedMode {
	implicit
	explicit
}

fn TaggedMode.from_string(s string) !TaggedMode {
	match s {
		'explicit' { return .explicit }
		'implicit' { return .implicit }
		else { return error('Bad string for tagged mode') }
	}
}

// Tagged type element
pub struct TaggedType {
mut:
	// class of TaggedType element was default to .context_specific
	outer_tag Tag
	mode      TaggedMode = .explicit
	// Element being tagged
	inner_el Element
}

// new creates a new TaggedType
pub fn TaggedType.new(el Element, tagmode TaggedMode, outer_tag Tag) !TaggedType {
	// Tagged type should in constructed form
	if !outer_tag.is_constructed() {
		return error('TaggedType tag should in constructed form')
	}
	return TaggedType{
		outer_tag: outer_tag
		mode:      tagmode
		inner_el:  el
	}
}

// explicit creates a new TaggedType with .explicit tagged mode.
pub fn TaggedType.explicit(el Element, outer_tag Tag) !TaggedType {
	return TaggedType.new(el, .explicit, outer_tag)
}

// implicit creates a new TaggedType with .implicit tagged mode for inner element el
pub fn TaggedType.implicit(el Element, outer_tag Tag) !TaggedType {
	return TaggedType.new(el, .implicit, outer_tag)
}

// explicit_context creates explicit mode of TaggedType for inner element el with tag has a .context_specific TagClass
// and expected (outer) tag number is set into tagnum
pub fn TaggedType.explicit_context(el Element, tagnum int) !TaggedType {
	tag := Tag.new(.context_specific, true, tagnum)!
	tt := TaggedType.explicit(el, tag)!
	return tt
}

// implicit_context creates implicit mode of TaggedType for inner element el with tag has a .context_specific TagClass
// and expected (outer) tag number is set into tagnum
pub fn TaggedType.implicit_context(el Element, tagnum int) !TaggedType {
	tag := Tag.new(.context_specific, true, tagnum)!
	tt := TaggedType.implicit(el, tag)!
	return tt
}

// tag returns outer tag of TaggedType
pub fn (tt TaggedType) tag() Tag {
	return tt.outer_tag
}

pub fn (tt TaggedType) tagged_mode() TaggedMode {
	return tt.mode
}

pub fn (tt TaggedType) payload(p Params) ![]u8 {
	// if mode is .explicit, the payload is serialized tt.inner_el element
	// and if .implicit, the payload is tt.inner_el payload
	if tt.mode == .explicit {
		mut out := []u8{}
		tt.inner_el.encode(mut out, p)!
		return out
	}
	// otherwise is in implicit mode
	payload := tt.inner_el.payload(p)!
	return payload
}

pub fn (tt TaggedType) length(p Params) !int {
	mut n := 0
	// in .explicit, n := tag+lengt+payload
	if tt.mode == .explicit {
		n += tt.inner_el.tag().packed_length(p)!
		len := tt.inner_el.length(p)!
		xlen := Length.from_i64(len)!
		n += xlen.packed_length(p)!
		n += len
	} else {
		// .implicit mode, just the payload
		n += tt.inner_el.length(p)!
	}

	return n
}

pub fn (tt TaggedType) packed_length(p Params) !int {
	mut n := 0
	match tt.mode {
		.explicit {
			// when in explicit mode, outer tag and length is appended to packed inner element
			n += tt.outer_tag.packed_length(p)!
			// inner_length also included length of tag and length of inner Element
			inner_length := tt.inner_el.packed_length(p)!

			tt_length := Length.from_i64(inner_length)!
			n += tt_length.packed_length(p)!
			n += inner_length
		}
		.implicit {
			// when in implicit mode, inner tag and length of inner element being replaced by outer tag and length
			n += tt.outer_tag.packed_length(p)!
			// in implicit mode, inner_length only contains inner_el.payload.len length (without tag and length)
			inner := tt.inner_el.payload(p)!
			inner_length := inner.len
			tt_length := Length.from_i64(inner_length)!
			n += tt_length.packed_length(p)!
			n += inner_length
		}
	}
	return n
}

pub fn (tt TaggedType) encode(mut dst []u8, p Params) ! {
	// TaggedType tag should in constructed form
	if !tt.outer_tag.is_constructed() {
		return error('TaggedType tag should in constructed form')
	}
	if p.rule != .der && p.rule != .ber {
		return error('TaggedType: unsupported rule')
	}
	match tt.mode {
		.explicit {
			// wraps the inner element with this tag and length
			tt.outer_tag.encode(mut dst, p)!
			length := tt.inner_el.packed_length(p)!
			len := Length.from_i64(length)!
			len.encode(mut dst, p)!
			tt.inner_el.encode(mut dst, p)!
		}
		.implicit {
			// replace the tag.of inner element with this tag
			tt.outer_tag.encode(mut dst)!
			payload := tt.inner_el.payload(p)!
			length := Length.from_i64(payload.len)!
			length.encode(mut dst, p)!
			dst << payload
		}
	}
}

pub fn TaggedType.decode(src []u8, loc i64, tm TaggedMode, inner_tag Tag, p Params) !(TaggedType, i64) {
	// TaggedType without inner element is not make sense
	if src.len < 4 {
		return error('TaggedType: bytes underflow')
	}
	raw, next := RawElement.decode(src, loc, p)!
	// TODO: check the tag, do we need .class == .context_specific
	// in explicit context, the tag should be in constructed form
	// raw.tag is outer_tag
	if !raw.tag.is_constructed() {
		return error('TaggedType: tag check failed, .explicit should be constructed')
	}
	if raw.payload.len == 0 {
		// its bad TaggedType with len==0, ie, without contents
		return error('TaggedType: len==0')
	}
	bytes := raw.payload

	match tm {
		.explicit {
			// when explicit, read element from bytes
			inner_raw, idx := RawElement.decode(bytes, 0, p)!
			if idx != bytes.len {
				return error('unmatching idx and bytes.len')
			}
			inn_sub := inner_raw.payload
			inner_el := if inner_raw.tag.is_constructed() {
				parse_constructed_element(inner_raw.tag, inn_sub)!
			} else {
				parse_primitive_element(inner_raw.tag, inn_sub)!
			}

			if inner_el.tag() != inner_tag {
				return error('unexpected inner tag')
			}
			tt := TaggedType{
				outer_tag: raw.tag
				mode:      .explicit
				inner_el:  inner_el
			}
			return tt, next
		}
		.implicit {
			// when in .implicit mode, inner tag is unknown, so we pass inner_tag as expected tag
			// the bytes is the values of the element
			inner := RawElement{
				tag:     inner_tag
				payload: bytes
			}
			tt := TaggedType{
				outer_tag: raw.tag
				mode:      .implicit
				inner_el:  inner
			}
			return tt, next
		}
	}
}

pub fn (tt TaggedType) inner_element() Element {
	return tt.inner_el
}

// from_raw_element treats this RawElement as TaggedType with mode m and inner element
pub fn TaggedType.from_raw_element(r RawElement, m TaggedMode, inner_tag Tag, p Params) !TaggedType {
	return r.as_tagged(m, inner_tag, p)!
}

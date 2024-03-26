// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// EXPLICIT and IMPLICIT
//
// mode of context specific wrapping. explicit mode add new tag
// to the existing object, implicit mode replaces tag of original object.
pub enum TaggedMode {
	implicit
	explicit
}

// Tagged type element
pub struct TaggedType {
mut:
	// class of TaggedType element was default to .context_specific
	outer_tag Tag
	mode      TaggedMode = .explicit
pub:
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
		mode: tagmode
		inner_el: el
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

// explicit_context creates explicit mode of TaggedType for inner element el with tag has a .context_specific Class
// and expected (outer) tag number is set into tagnum
pub fn TaggedType.explicit_context(el Element, tagnum int) !TaggedType {
	tag := new_tag(.context_specific, true, tagnum)!
	tt := TaggedType.explicit(el, tag)!
	return tt
}

// implicit_context creates implicit mode of TaggedType for inner element el with tag has a .context_specific Class
// and expected (outer) tag number is set into tagnum
pub fn TaggedType.implicit_context(el Element, tagnum int) !TaggedType {
	tag := new_tag(.context_specific, true, tagnum)!
	tt := TaggedType.implicit(el, tag)!
	return tt
}

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

pub fn (tt TaggedType) length(p Params) int {
	mut n := 0
	// in .explicit, n := tag+lengt+payload
	if tt.mode == .explicit {
		n += tt.inner_el.tag().packed_length(p)
		len := tt.inner_el.length(p)
		xlen := Length.from_i64(len) or { panic(err) }
		n += xlen.packed_length(p)
		n += len
	} else {
		// .implicit mode, just the payload
		n += tt.inner_el.length(p)
	}
	return n
}

pub fn (tt TaggedType) packed_length(p Params) int {
	mut n := 0
	match tt.mode {
		.explicit {
			// when in explicit mode, outer tag and length is appended to packed inner element
			n += tt.outer_tag.packed_length(p)
			// inner_length also included length of tag and length of inner Element
			inner_length := tt.inner_el.packed_length(p)

			tt_length := Length.from_i64(inner_length) or { panic(err) }
			n += tt_length.packed_length(p)
			n += inner_length
		}
		.implicit {
			// when in implicit mode, inner tag and length of inner element being replaced by outer tag and length
			n += tt.outer_tag.packed_length(p)
			// in implicit mode, inner_length only contains inner_el.payload.len length (without tag and length)
			inner := tt.inner_el.payload(p) or { panic(err) }
			inner_length := inner.len
			tt_length := Length.from_i64(inner_length) or { panic(err) }
			n += tt_length.packed_length(p)
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
	if p.mode != .der && p.mode != .ber {
		return error('TaggedType: unsupported mode')
	}
	match tt.mode {
		.explicit {
			// wraps the inner element with this tag and length
			tt.outer_tag.encode(mut dst, p)!
			length := tt.inner_el.packed_length(p)
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
				mode: .explicit
				inner_el: inner_el
			}
			return tt, next
		}
		.implicit {
			// when in .implicit mode, inner tag is unknown, so we pass inner_tag as expected tag
			// the bytes is the values of the element
			inner := RawElement{
				tag: inner_tag
				payload: bytes
			}
			tt := TaggedType{
				outer_tag: raw.tag
				mode: .implicit
				inner_el: inner
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

/*
enum Mode {
	explicit = 0
	implicit = 1
}

// Tagged represents wrapper of tagged object from original object in inner.
struct Tagged {
	expected Tag     // expected tag
	mode     Mode    // tagged mode, implicit or explicit
	inner    Encoder // inner object being wrapped
}

// new_explicit_tagged creates new explicit tagged object with class and tag number set to `class` and `tagnum` respectively.
fn new_explicit_tagged(asn Encoder, class Class, tagnum int) Tagged {
	return Tagged{
		expected: new_tag(class, true, tagnum)
		mode: .explicit
		inner: asn
	}
}

// new_implicit_tagged creates new implicit tagged object with class and tag number set to `class` and `tagnum` respectively.
fn new_implicit_tagged(asn Encoder, class Class, tagnum int) Tagged {
	inner_tag := asn.tag()
	return Tagged{
		expected: new_tag(class, inner_tag.constructed, tagnum)
		mode: .implicit
		inner: asn
	}
}

// new_implicit_context creates new implicit mode of context specific class of tagged object from original
// ASN.1 object with new tag number sets to tagnum.
pub fn new_implicit_context(asn Encoder, tagnum int) Tagged {
	return new_implicit_tagged(asn, .context, tagnum)
}

fn read_implicit_context(tag Tag, contents []u8) !Tagged {
	if !tag.is_context() {
		return error('not context class')
	}
	if tag.is_constructed() {
		return error('read in constructed tag')
	}
	element := der_decode(contents)!
	ctx := new_implicit_context(element, tag.number)
	return ctx
}

// new_explicit_context creates new explicit mode of context specific class of tagged object
// from original ASN.1 object with tag number sets to tagnum.
pub fn new_explicit_context(asn Encoder, tagnum int) Tagged {
	return new_explicit_tagged(asn, .context, tagnum)
}

pub fn read_explicit_context(tag Tag, contents []u8) !Tagged {
	if !tag.is_context() {
		return error('not context class')
	}
	if !tag.is_constructed() {
		return error('not constructed tag')
	}

	element := der_decode(contents)!
	ctx := new_explicit_context(element, tag.number)
	return ctx
}

// decode_explicit_context tries to read data in src and creates context tagged object from der encoded
// data. The schema of data should encoded in explicit mode.
fn decode_explicit_context(src []u8) !Tagged {
	tag, pos := read_tag(src, 0)!
	length, idx := decode_length(src, pos)!

	contents := read_bytes(src, idx, length)!
	// try to read element
	// el := decode_element(contents)!

	ctx := read_explicit_context(tag, contents)!
	return ctx
}

// tag returns outer tag
pub fn (ctx Tagged) tag() Tag {
	return ctx.expected
}

// inner_tag return inner tag of the inner object being wrapped
pub fn (ctx Tagged) inner_tag() Tag {
	return ctx.inner.tag()
}

// as_inner returns inner object being wrapped
pub fn (ctx Tagged) as_inner() Encoder {
	return ctx.inner
}

// length returns the length of the context tagged object
pub fn (ctx Tagged) length() int {
	match ctx.mode {
		// explicit mode adds context specitif tag to the existing object
		// so, the original (inner) object size becomes length of the
		// new object.
		.explicit {
			return ctx.inner.size()
		}
		// implicit mode replaces tag of original (inner) object, so the length
		// of the object still same with original (inner) length
		.implicit {
			return ctx.inner.length()
		}
	}
}

// size returns sizes of context specific tagged object.
// When in explicit mode, the size of object was sum of length of the outer tag,
// length of the length part and inner size.
// and in implicit mode, the size was total (sum) of size of inner object,
// and length of outer tag.
pub fn (ctx Tagged) size() int {
	match ctx.mode {
		.explicit {
			// size := expected tag length + length of context tagged object + size of inner object
			mut size := 0
			taglen := calc_tag_length(ctx.tag())
			size += taglen

			// length of length
			lol := calc_length_of_length(ctx.length())
			size += int(lol)

			// plus size of inner object
			size += ctx.length()

			return size
		}
		// size := expected tag length + size of inner object
		.implicit {
			taglen := calc_tag_length(ctx.tag())
			size := taglen + ctx.inner.size()
			return size
		}
	}
}

// encode serializes context tagged object to array of bytes.
// Its different between tagged mode explicit and implicit.
pub fn (ctx Tagged) encode() ![]u8 {
	tag := ctx.tag()
	match ctx.mode {
		.explicit {
			// make sure its context specific tag and constructed bit was set

			if !tag.is_context() && !tag.is_constructed() {
				return error('expected tag was not context or constructed bit not set')
			}
			mut dst := []u8{}

			serialize_tag(mut dst, tag)
			serialize_length(mut dst, ctx.length())

			data := ctx.inner.encode()!
			dst << data

			return dst
		}
		.implicit {
			// make sure its context specific tag
			if !tag.is_context() {
				return error('expected tag was not context specific class')
			}
			tg := Tag{
				class: .context
				constructed: ctx.inner.tag().constructed
				number: ctx.expected.number
			}
			data := ctx.inner.contents()!
			mut dst := []u8{}

			serialize_tag(mut dst, tg)
			serialize_length(mut dst, ctx.length())

			dst << data

			return dst
		}
	}
}
*/

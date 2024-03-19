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
struct TaggedType {
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

fn (tt TaggedType) packed_length() int {
	mut n := 0
	match tt.mode {
		.explicit {
			// when in explicit mode, outer tag and length is appended to packed inner element
			n += tt.outer_tag.packed_length()
			// inner_length also included length of tag and length of inner Element
			inner_length := tt.inner_el.packed_length()

			tt_length := Length.from_i64(inner_length) or { panic(err) }
			n += tt_length.packed_length()
			n += inner_length
		}
		.implicit {
			// when in implicit mode, inner tag and length of inner element being replaced by outer tag and length
			n += tt.outer_tag.packed_length()
			// in implicit mode, inner_length only contains inner_el.payload.len length (without tag and length)
			inner := tt.inner_el.payload() or { panic(err) }
			inner_length := inner.len
			tt_length := Length.from_i64(inner_length) or { panic(err) }
			n += tt_length.packed_length()
			n += inner_length
		}
	}
	return n
}

pub fn (tt TaggedType) pack_to_asn1(mut dst []u8, p Params) ! {
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
			tt.outer_tag.pack_to_asn1(mut dst, p)!
			length := tt.inner_el.packed_length()
			len := Length.from_i64(length)!
			len.pack_to_asn1(mut dst, p)!
			tt.inner_el.pack_to_asn1(mut dst, p)!
		}
		.implicit {
			// replace the tag.of inner element with this tag
			tt.outer_tag.pack_to_asn1(mut dst)!
			payload := tt.inner_el.payload()!
			length := Length.from_i64(payload.len)!
			length.pack_to_asn1(mut dst, p)!
			dst << payload
		}
	}
}

pub fn TaggedType.unpack_from_asn1(src []u8, loc i64, tm TaggedMode, inner_tag Tag, p Params) !(TaggedType, i64) {
	if src.len < 2 {
		return error('TaggedType: bytes underflow')
	}
	if p.mode != .der && p.mode != .ber {
		return error('TaggedType: unsupported mode')
	}
	if loc > src.len {
		return error('TaggedType: bad position offset')
	}
	// external tag
	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	// TODO: check the tag, do we need .class == .context_specific
	// in explicit context, the tag should be in constructed form
	if tm == .explicit && !tag.is_constructed() {
		return error('TaggedType: tag check failed, .explicit should be constructed')
	}
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	if len == 0 {
		// its bad TaggedType with len==0, ie, without contents
		return error('TaggedType: len==0')
	}
	if idx > src.len || idx + len > src.len {
		return error('TaggedType: truncated bytes')
	}
	// TODO: check the length, its safe to access bytes
	bytes := unsafe { src[idx..idx + len] }
	match tm {
		.explicit {
			// when explicit, unpack element from bytes
			inner, _ := RawElement.unpack_from_asn1(bytes, 0, p)!
			// TODO: parse nested element
			if inner.tag() != inner_tag {
				return error('unexpected inner tag')
			}

			tt := TaggedType{
				outer_tag: tag
				mode: .explicit
				inner_el: inner
			}
			return tt, idx + len
		}
		.implicit {
			// when in .implicit mode, inner tag is unknown, so we pass inner_tag as expected tag
			// the bytes is the values of the element
			inner := RawElement{
				tag: inner_tag
				payload: bytes
			}
			tt := TaggedType{
				outer_tag: tag
				mode: .implicit
				inner_el: inner
			}
			return tt, idx + len
		}
	}
}

// from_raw_element treats this RawElement as TaggedType with mode m and inner element
fn TaggedType.from_raw_element(r RawElement, m TaggedMode, inner Element, p Params) !TaggedType {
	if !r.tag.is_constructed() {
		return error('the tag of provided RawElement is not constructed')
	}
	match m {
		// treats r.payload as an explicit type
		.explicit {
			tag, pos := Tag.unpack_from_asn1(r.payload, 0, p)!
			if tag != inner.tag() {
				return error('gets different tag')
			}
			len, idx := Length.unpack_from_asn1(r.payload, pos, p)!
			if idx != r.payload.len {
				return error('gets different length')
			}
			bytes := unsafe { r.payload[idx..idx + len] }
			if bytes != inner.payload()! {
				return error('differs in content')
			}
			tt := TaggedType{
				outer_tag: r.tag
				mode: .explicit
				inner_el: inner
			}
			return tt
		}
		// treats r.payload as contents
		.implicit {
			// payload := inner.payload()!
			if inner.payload()! != r.payload {
				return error('implicit differs in content')
			}
			tt := TaggedType{
				outer_tag: r.tag
				mode: .implicit
				inner_el: inner
			}
			return tt
		}
	}
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

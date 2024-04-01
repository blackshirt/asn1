h// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// EXPLICIT and IMPLICIT
//
// mode of context specific wrapping. explicit mode add new tag
// to the existing object, implicit mode replaces tag of original object.
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
	if !tag.is_constructed() {
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

pub fn Tagged.decode(src []u8, m Mode, inner_tag Tag) !Tagged {
	tag, pos := read_tag(src, 0)!
	if !tag.constructed {
		return error('Tagged should be constructed')
	}
	length, idx := decode_length(src, pos)!
	contents := read_bytes(src, idx, length)!
	match m {
		.explicit {
			// when explicit, the contents is an asn1 structure
			etag, epos := read_tag(contents, 0)!
			if etag != inner_tag {
				return error('unmatching explicit tag')
			}
			elength, eidx := decode_length(contents, epos)!
			bytes := read_bytes(contents, eidx, elength)!
			inner := new_asn_object(inner_tag.class, inner_tag.constructed, inner_tag.number,
				bytes)
			tt := Tagged{
				expected: tag
				mode: .explicit
				inner: inner
			}
			return tt
		}
		.implicit {
			// when implicit, contents is the real inner contents
			inner := new_asn_object(inner_tag.class, inner_tag.constructed, inner_tag.number,
				contents)
			tt := Tagged{
				expected: tag
				mode: .implicit
				inner: inner
			}
			return tt
		}
	}
}

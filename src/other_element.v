// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Limited support for other of ASN.1 Element.
//

// ASN.1 RawElement.
@[noinit]
pub struct RawElement {
mut:
	// The (outer) tag is the tag of the TLV, if this a wrpper.
	tag Tag
	// `content` is the value of a TLV. Its depends on the context.
	content []u8
}

// outer tag when its a wrapper.
pub fn (r RawElement) tag() Tag {
	return r.tag
}

pub fn (r RawElement) inner_tag(expected Tag, mode TaggedMode) !Tag {
	elem := r.inner_element(expected, mode)!
	return elem.tag()
}

pub fn (r RawElement) inner_element(expected Tag, mode TaggedMode) !Element {
	if r.tag.class == .universal {
		return error('RawElement with universal class has no inner element')
	}
	if mode == .explicit {
		if !r.tag.constructed {
			return error('Its possible to read inner within primitive element with explicit mode')
		}
	}
	// in implicit, r.content is inner element content with inner tag
	if mode == .implicit {
		elem := parse_element(expected, r.content)!
		return elem
	}
	// otherwise, treats it in explicit mode.
	// read an inner tag from r.content
	mut p := Parser.new(r.content)
	tag := p.peek_tag()!
	if !tag.equal(expected) {
		return error('Get unexpected inner tag')
	}
	el := p.read_tlv()!
	// should finish
	p.finish()!
	return el
}

pub fn (r RawElement) payload() ![]u8 {
	return r.content
}

pub fn RawElement.new(tag Tag, content []u8) RawElement {
	new := RawElement{
		tag:     tag
		content: content
	}
	return new
}

// ContextSpecific tagged type element.
// Its always constructed (non-primitive).
@[noinit]
pub struct ContextElement {
mut:
	outer_tag Tag  // outer tag
	content   []u8 // just content or serialized inner element, depends on mode.
	inner_tag ?Tag
	mode      ?TaggedMode // mode of tagged type
}

// ContextElement.new creates a new tagged type of ContextElement from some element in inner.
pub fn ContextElement.new(tagnum int, mode TaggedMode, inner Element) !ContextElement {
	if tagnum < 0 || tagnum > max_tag_number {
		return error('Unallowed tagnum was provided')
	}

	// check universal-ity of the inner element
	if inner.tag().class != .universal {
		return asn1_error(.invalid_tag_class, 'ContextElement', '${inner.tag().class}',
			'universal')
	}
	// gets inner form, was used if in implicit mode, or constructed in explicit mode.
	inner_form := inner.tag().is_constructed()
	constructed := if mode == .implicit { inner_form } else { true }
	content := if mode == .implicit { inner.payload()! } else { encode_with_rule(inner, .der)! }

	outer_tag := Tag.new(.context_specific, constructed, tagnum)!

	ctx := ContextElement{
		outer_tag: outer_tag
		content:   content
		inner_tag: inner.tag()
		mode:      mode
	}
	return ctx
}

pub fn (mut ctx ContextElement) set_inner_tag(tag Tag) ! {
	ctx.inner_tag = tag
	ctx.check_inner_tag()!
}

pub fn (mut ctx ContextElement) set_mode(mode TaggedMode) {
	ctx.mode = mode
}

fn (ctx ContextElement) check_inner_tag() ! {
	mode := ctx.mode or { return error('You dont set any context_specific mode') }
	if mode != .explicit {
		return
	}
	// read an inner tag from content
	tag, _ := Tag.decode_with_rule(ctx.content, 0, .der)!
	inner_tag := ctx.inner_tag or { return error('You dont set an inner_tag') }
	if !tag.equal(inner_tag) {
		return error('Get unexpected inner tag from bytes')
	}
}

pub fn (ctx ContextElement) tag() Tag {
	return ctx.outer_tag
}

pub fn (ctx ContextElement) inner_tag() ?Tag {
	return ctx.inner_tag
}

pub fn (ctx ContextElement) payload() ![]u8 {
	return ctx.content
}

// `explicit_context` creates new ContextElement with explicit mode.
pub fn ContextElement.explicit_context(tagnum int, inner Element) !ContextElement {
	return ContextElement.new(tagnum, .explicit, inner)!
}

// implicit_context creates new ContextElement with implicit mode.
pub fn ContextElement.implicit_context(tagnum int, inner Element) !ContextElement {
	return ContextElement.new(tagnum, .implicit, inner)!
}

fn ContextElement.decode_raw(bytes []u8) !(ContextElement, int) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, .der)!
	if tag.class != .context_specific {
		return asn1_error(.invalid_tag_class, 'ContextElement', '${tag.class}', 'context_specific')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, .der)!
	content := if length == 0 {
		[]u8{}
	} else {
		if content_pos >= bytes.len || content_pos + length > bytes.len {
			return error('ContextElement: truncated payload bytes')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}
	next := content_pos + length
	// Raw ContextElement, you should provide mode and inner tag.
	ctx := ContextElement{
		outer_tag: tag
		content:   content
	}
	return ctx, next
}

fn ContextElement.decode_with_options(bytes []u8, opt string) !(ContextElement, int) {
	if opt.len == 0 {
		return ContextElement.decode_raw(bytes)!
	}
	fo := FieldOptions.from_string(opt)!
	// get mode and inner tag
	if !valid_mode_value(fo.mode) {
		return error('Get unexpected mode option for ContextElement')
	}
	mode := TaggedMode.from_string(fo.mode)!
	inner_tag := universal_tag_from_int(fo.inner)!

	// outer tag from bytes
	tag, length_pos := Tag.decode_with_rule(bytes, 0, .der)!
	if tag.class != .context_specific {
		return error('Get non ContextSpecific tag')
	}

	// if mode is explicit without constructed form, its would return on error.
	if mode == .explicit {
		if !tag.constructed {
			return error('explicit need constructed form')
		}
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, .der)!
	content := if length == 0 {
		[]u8{}
	} else {
		if content_pos >= bytes.len || content_pos + length > bytes.len {
			return error('ContextElement: truncated payload bytes')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}
	next := content_pos + length

	if mode == .implicit {
		ctx := ContextElement{
			outer_tag: tag
			content:   content
			inner_tag: inner_tag
			mode:      .implicit
		}
		return ctx, next
	}
	// explicit one, build ContextElement and performs checks for inner_tag validity.
	ctx := ContextElement{
		outer_tag: tag
		content:   content
		inner_tag: inner_tag
		mode:      .explicit
	}
	ctx.check_inner_tag()!

	return ctx, next
}

fn ContextElement.from_bytes(bytes []u8) !ContextElement {
	return error('not implemented')
}

@[noinit]
pub struct ApplicationElement {
	RawElement
}

pub fn ApplicationElement.new(constructed bool, tagnum int, content []u8) !ApplicationElement {
	tag := Tag.new(.application, constructed, tagnum)!
	return ApplicationElement{
		tag:     tag
		content: content
	}
}

pub fn (app ApplicationElement) tag() Tag {
	return app.tag
}

pub fn (app ApplicationElement) payload() ![]u8 {
	return app.content
}

@[noinit]
pub struct PrivateELement {
	RawElement
}

pub fn PrivateELement.new(constructed bool, tagnum int, content []u8) !PrivateELement {
	tag := Tag.new(.private, constructed, tagnum)!
	return PrivateELement{
		tag:     tag
		content: content
	}
}

pub fn (prv PrivateELement) tag() Tag {
	return prv.tag
}

pub fn (prv PrivateELement) payload() ![]u8 {
	return prv.content
}

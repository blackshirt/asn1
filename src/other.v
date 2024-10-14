// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Limited support for other class of ASN.1 Element
//

@[noinit]
pub struct Asn1Element {
mut:
	// tag is the tag of the TLV
	tag Tag
	// `content` is the value of a TLV
	content []u8
}

pub fn (a Asn1Element) tag() Tag {
	return a.tag
}

pub fn (a Asn1Element) payload() ![]u8 {
	return a.content
}

pub fn Asn1Element.new(tag Tag, content []u8) !Asn1Element {
	return Asn1Element.new_with_rule(tag, content, .der)!
}

fn Asn1Element.new_with_rule(tag Tag, content []u8, rule EncodingRule) !Asn1Element {
	new := Asn1Element{
		tag:     tag
		content: content
	}
	return new
}

@[noinit]
pub struct ContextElement {
mut:
	outer_tag Tag  // outer tag number
	inner_tag ?Tag // inner tag,
	// when in .explicit mode, the content should include inner_tag bytes
	content []u8        // payload
	mode    ?TaggedMode // mode of tagged type
}

pub fn ContextElement.new(mode TaggedMode, tagnum int, inner Element) !ContextElement {
	tag := Tag.new(.context_specific, true, tagnum)!
	mut content := []u8{}
	if mode == .explicit {
		content = encode(inner)!
	} else {
		content = inner.payload()!
	}
	ctx := ContextElement{
		outer_tag: tag
		inner_tag: inner.tag()
		content:   content
		mode:      mode
	}

	return ctx
}

fn (mut ctx ContextElement) set_inner_tag(tag Tag) ! {
	if ctx.inner_tag != none {
		return error('already has inner_tag')
	}
	if ctx.mode == none {
		return error('You should set mode first')
	}
	ctx.inner_tag = tag
}

fn (mut ctx ContextElement) set_ctx_mode(mode TaggedMode) ! {
	if ctx.mode != none {
		return error('already has ctx mode')
	}
	ctx.mode = mode
}

pub fn explicit_context(tagnum int, inner Element) !ContextElement {
	return ContextElement.new(.explicit, tagnum, inner)!
}

pub fn implicit_context(tagnum int, inner Element) !ContextElement {
	return ContextElement.new(.implicit, tagnum, inner)!
}

fn (ce ContextElement) read_innertag_from_content() !Tag {
	if ce.mode == none {
		return error('Mode is not set')
	}
	ctx_mode := ce.mode or { return error('mode is not set') }
	if ctx_mode == .implicit {
		return error('You can not read inner_tag from implicit mode')
	}
	tag, _ := Tag.from_bytes(ce.content)!
	return tag
}

fn ContextElement.decode(bytes []u8) !(ContextElement, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, .der)!
	if tag.tag_class() != .context_specific {
		return error('Get non ContextSpecific tag')
	}
	if !tag.is_constructed() {
		return error('Get non-constructed ContextSpecific tag')
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
	ctx := parse_context_specific(tag, content)!
	return ctx, next
}

fn ContextElement.decode_with_mode(bytes []u8, mode TaggedMode) !(ContextElement, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, .der)!
	if tag.tag_class() != .context_specific {
		return error('Get non ContextSpecific tag')
	}
	if !tag.is_constructed() {
		return error('Get non-constructed ContextSpecific tag')
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

	mut ctx := parse_context_specific_with_mode(tag, content, mode)!
	ctx_mode := ctx.mode or { return error('Mode is not set') }
	if ctx_mode == .explicit {
		inner_tag := ctx.read_innertag_from_content()!
		ctx.set_inner_tag(inner_tag)!
	}
	return ctx, next
}

fn (ce ContextElement) inner_element() !Element {
	return error('not implemented')
}

// outer tag
pub fn (ce ContextElement) tag() Tag {
	return ce.outer_tag
}

pub fn (ce ContextElement) payload() ![]u8 {
	return ce.content
}

pub fn (ce ContextElement) inner_tag() ?Tag {
	return ce.inner_tag
}

fn ContextElement.from_bytes(bytes []u8) !ContextElement {
	return error('not implemented')
}

@[noinit]
pub struct ApplicationElement {
	Asn1Element
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
	Asn1Element
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

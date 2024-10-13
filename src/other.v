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
	// inner only for .universal class
	if inner.tag().tag_class() != .universal {
		return error('cant create ContextElement from non-universal class')
	}
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

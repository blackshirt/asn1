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
	// Optional fields
	inner_tag     ?Tag
	mode          ?TaggedMode
	default_value ?Element
}

pub fn RawElement.new(tag Tag, content []u8) !RawElement {
	// universal class with constructed form only valid for sequence(of) and set(of) type.
	if tag.class == .universal && tag.constructed {
		if tag.number != int(TagType.sequence) && tag.number != int(TagType.set) {
			return asn1_error(.invalid_tag_format, '${@METHOD}', 'required sequence or set number')!
		}
	}
	// otherwise, treats as a RawElement
	return RawElement{
		tag:     tag
		content: content
	}
}

// wrap into RawElement
pub fn RawElement.from_element(el Element, cls TagClass, tagnum int, mode TaggedMode) !RawElement {
	if cls == .universal {
		return asn1_error(.unallowed_operation, '${@METHOD}', 'wrap with universal class is unallowed')!
	}
	inner_form := el.tag().is_constructed()
	constructed := if mode == .explicit { true } else { inner_form }
	content := if mode == .explicit { encode_with_rule(el, .der)! } else { el.payload()! }

	outer_tag := Tag.new(cls, constructed, tagnum)!
	raw := RawElement{
		tag:       outer_tag
		content:   content
		inner_tag: el.tag()
		mode:      mode
	}

	return raw
}

pub fn (r RawElement) payload() ![]u8 {
	return r.content
}

pub fn (mut r RawElement) set_raw_mode(mode TaggedMode) ! {
	if r.mode != none {
		return asn1_error(.unallowed_operation, '${@METHOD}', 'r.mode != none')!
	}
	if r.tag.class == .universal {
		return asn1_error(.unallowed_operation, '${@METHOD}', 'No need it on universal class')!
	}
	r.mode = mode
}

pub fn (mut r RawElement) set_inner_tag(inner_tag Tag) ! {
	if r.inner_tag != none {
		return asn1_error(.unallowed_operation, '${@METHOD}', 'r.inner_tag != none')!
	}
	if r.tag.class == .universal {
		return asn1_error(.unallowed_operation, '${@METHOD}', 'No need it on universal class')!
	}
	mode := r.mode or {
		return asn1_error(.unmeet_requirement, '${@METHOD}', 'set the mode first')!
	}

	if mode == .explicit {
		if !r.tag.constructed {
			return asn1_error(.unmeet_requirement, '${@METHOD}', 'explicit should be constructed')!
		}
		// check inner_tag
		itt, _ := Tag.decode(r.content)!
		if !itt.equal(inner_tag) {
			return asn1_error(.unmeet_requirement, '${@METHOD}', 'unequal supplied tag')!
		}
	}
	r.inner_tag = inner_tag
}

// outer tag when its a wrapper.
pub fn (r RawElement) tag() Tag {
	return r.tag
}

pub fn (r RawElement) inner_tag() !Tag {
	inner_tag := r.inner_tag or {
		return asn1_error(.invalid_value, '${@METHOD}', ' r.inner_tag is not set')!
	}

	return inner_tag
}

pub fn (r RawElement) inner_element() !Element {
	if r.tag.class == .universal {
		asn1_error(.unallowed_operation, '${@METHOD}', 'inner element from universal class is not availables')!
	}
	mode := r.mode or { return err }

	inner_tag := r.inner_tag or { return err }

	if mode == .explicit {
		if !r.tag.constructed {
			asn1_error(.unmeet_requirement, '${@METHOD}', 'tag should be constructed when in explicit')!
		}
	}
	// in implicit, r.content is inner element content with inner tag
	if mode == .implicit {
		elem := parse_element(inner_tag, r.content)!
		return elem
	}
	// otherwise, treats it in explicit mode.
	// read an inner tag from r.content
	mut p := Parser.new(r.content)
	tag := p.peek_tag()!
	if !tag.equal(inner_tag) {
		asn1_error(.invalid_value, '${@METHOD}', 'gets unequal inner_tag')!
	}
	el := p.read_tlv()!
	// should finish
	p.finish()!
	return el
}

fn (r RawElement) check_inner_tag() ! {
	if r.tag.class == .universal {
		return asn1_error(.unallowed_operation, '${@METHOD}', 'Universal class dont have inner tag')!
	}
	mode := r.mode or { return error('You dont set any mode') }
	if mode != .explicit {
		return
	}
	// read an inner tag from content
	tag, _ := Tag.decode_with_rule(r.content, 0, .der)!
	inner_tag := r.inner_tag or { return error('You dont set an inner_tag') }
	if !tag.equal(inner_tag) {
		return error('Get unexpected inner tag from bytes')
	}
}

// ContextSpecific tagged type element.
// Its always constructed (non-primitive).
@[noinit]
pub struct ContextElement {
	RawElement
}

// ContextElement.new creates a new tagged type of ContextElement from some element in inner.
pub fn ContextElement.new(inner Element, tagnum int, mode TaggedMode) !ContextElement {
	if tagnum < 0 || tagnum > max_tag_number {
		return error('Unallowed tagnum was provided')
	}
	raw := RawElement.from_element(inner, .context_specific, tagnum, mode)!

	ctx := ContextElement{raw}
	return ctx
}

pub fn (ctx ContextElement) tag() Tag {
	return ctx.tag
}

pub fn (ctx ContextElement) payload() ![]u8 {
	return ctx.content
}

// `explicit_context` creates new ContextElement with explicit mode.
pub fn ContextElement.explicit_context(inner Element, tagnum int) !ContextElement {
	return ContextElement.new(inner, tagnum, .explicit)!
}

// implicit_context creates new ContextElement with implicit mode.
pub fn ContextElement.implicit_context(inner Element, tagnum int) !ContextElement {
	return ContextElement.new(inner, tagnum, .implicit)!
}

fn ContextElement.decode_raw(bytes []u8) !(ContextElement, int) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, .der)!
	if tag.class != .context_specific {
		return asn1_error(.invalid_tag_class, 'ContextElement', 'context_specific')!
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
		tag:     tag
		content: content
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
			tag:       tag
			content:   content
			inner_tag: inner_tag
			mode:      .implicit
		}
		return ctx, next
	}
	// explicit one, build ContextElement and performs checks for inner_tag validity.
	ctx := ContextElement{
		tag:       tag
		content:   content
		inner_tag: inner_tag
		mode:      .explicit
	}
	ctx.check_inner_tag()!

	return ctx, next
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

pub fn ApplicationElement.from_element(inner Element, tagnum int, mode TaggedMode) !ApplicationElement {
	if tagnum < 0 || tagnum > max_tag_number {
		return error('Unallowed tagnum was provided')
	}
	raw := RawElement.from_element(inner, .application, tagnum, mode)!

	app := ApplicationElement{raw}
	return app
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

pub fn PrivateELement.from_element(inner Element, tagnum int, mode TaggedMode) !PrivateELement {
	if tagnum < 0 || tagnum > max_tag_number {
		return error('Unallowed tagnum was provided')
	}
	raw := RawElement.from_element(inner, .private, tagnum, mode)!

	app := PrivateELement{raw}
	return app
}

pub fn (prv PrivateELement) tag() Tag {
	return prv.tag
}

pub fn (prv PrivateELement) payload() ![]u8 {
	return prv.content
}

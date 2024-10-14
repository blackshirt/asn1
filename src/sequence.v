// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// SEQUENCE and SEQUENCE OF handling
//
// https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der
// These are two very different types.
// A SEQUENCE is equivalent to “struct” in most programming languages.
// It holds a fixed number of fields of different types.
// A SEQUENCE OF, holds an arbitrary number of fields of a single type.
// This is analogous to an array or a list in a programming language.
// Sequence structure can represents both SEQUENCE and SEQUENCE OF type.
// The encoding of a sequence value shall be constructed.
// in DER encoded of SEQUENCE or SET, never encode a default value.

// default tag of Sequence(Of)
const default_sequence_tag = Tag{.universal, true, int(TagType.sequence)}

// constant for sequence(of) and set(of) internal value 
const max_seqset_fields = 256 // max of seq size
const max_seqset_bytes = (1 << 23 - 1) // 8 MB
const default_seqset_fields = 64 // default size

@[noinit]
pub struct Sequence {
mut:
	//	maximal size of this sequence fields
	max_size int = default_seqset_fields
	// fields is the elements of the sequence
	fields []Element
}

pub fn (seq Sequence) tag() Tag {
	return default_sequence_tag
}

pub fn (seq Sequence) payload() ![]u8 {
	return seq.payload_with_rule(.der)!
}

fn (seq Sequence) payload_with_rule(rule EncodingRule) ![]u8 {
	mut out := []u8{}
	for el in seq.fields {
		obj := encode_with_rule(el, rule)!
		out << obj
	}
	return out
}

pub fn (seq Sequence) fields() []Element {
	return seq.fields
}

fn Sequence.parse(mut p Parser) !Sequence {
	return error('not yet implemented')
}

fn Sequence.decode(bytes []u8) !(Sequence, i64) {
	return Sequence.decode_with_rule(bytes, 0, .der)!
}

fn Sequence.decode_with_rule(bytes []u8, loc i64, rule EncodingRule) !(Sequence, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, loc, rule)!
	if !tag.equal(default_sequence_tag) {
		return error('Get unexpected non-sequence tag')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!
	payload := if length == 0 {
		[]u8{}
	} else {
		if content_pos + length > bytes.len {
			return error('Not enought bytes to read on')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}
	next := content_pos + length
	seq := Sequence.from_bytes(payload)!
	return seq, next
}

// bytes should seq.fields payload, not includes the tag
fn Sequence.from_bytes(bytes []u8) !Sequence {
	mut seq := Sequence{}
	if bytes.len == 0 {
		return seq
	}
	mut i := i64(0)
	for i < bytes.len {
		el, _ := Element.decode_with_rule(bytes, i, .der)!
		i += el.encoded_len()
		seq.add_element(el)!
	}
	if i > bytes.len {
		return error('i > bytes.len')
	}
	if i < bytes.len {
		return error('The src contains unprocessed bytes')
	}
	return seq
}

fn (mut seq Sequence) set_limit(limit int) ! {
	if limit > max_seqset_fields {
		return error('Provided limit was exceed current one')
	}
	seq.max_size = limit
}

// by default allow add with the same tag
fn (mut seq Sequence) add_element(el Element) ! {
	seq.force_add_element(el, false)!
}

// add_element allows adding a new element into current sequence fields.
// Its does not allow adding element when is already the same tag in the fields.
// but, some exception when you set force to true
fn (mut seq Sequence) force_add_element(el Element, force bool) ! {
	if seq.fields.len == 0 {
		// just adds it then return
		seq.fields << el
		return
	}

	for item in seq.fields {
		if item.equal_with(el) {
			return error('has already in the fields')
		}
	}
	filtered_by_tag := seq.fields.filter(it.equal_tag(el))
	if filtered_by_tag.len == 0 {
		seq.fields << el
		return
	} else {
		if !force {
			return error('You can not insert element without forcing')
		}
		seq.fields << el
		return
	}
}

// checks whether this sequence is SequenceOf[T]
fn (seq Sequence) is_sequence_of[T]() bool {
	return seq.fields.all(it is T)
}

// into_sequence_of[T] turns this sequence into SequenceOf[T]
fn (seq Sequence) into_sequence_of[T]() !SequenceOf[T] {
	if seq.is_sequence_of[T]() {
		return error('This sequence is not SequenceOf[T]')
	}
	mut sqof := SequenceOf[T]{}
	for el in seq.fields {
		obj := el.into_object[T]()!
		sqof.fields << obj
	}
	return sqof
}

// generic type aliases are not yet implemented
@[heap; noinit]
pub struct SequenceOf[T] {
mut:
	max_size int = default_seqset_fields
pub:
	fields []T
}

pub fn (so SequenceOf[T]) tag() Tag {
	return Tag{.universal, true, u32(TagType.sequence)}
}

pub fn (so SequenceOf[T]) payload() ![]u8 {
	return so.payload_with_rule(.der)!
}

fn (so SequenceOf[T]) payload_with_rule(rule EncodingRule) ![]u8 {
	$if T !is Element {
		return error('T is not an element')
	}
	mut out := []u8{}
	for el in so.fields {
		obj := encode_with_rule(el, rule)!
		out << obj
	}
	return out
}

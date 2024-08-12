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
pub struct Sequence {
mut:
	// The tag should represents sequence or sequenceof tag, ie, 0x30
	tag Tag = Tag{.universal, true, int(TagType.sequence)}
	// seqof should be set when this sequence is SequenceOf type
	seqof bool
	// elements of the sequence
	elements []Element
}

pub fn Sequence.new(seqof bool) !Sequence {
	tag := new_tag(.universal, true, int(TagType.sequence))!
	return Sequence.new_with_tag(tag, seqof)
}

// new_with_tag creates a new empty Sequence with tag `tag`. If seqof is true, a new Sequence
// should be treated as a SequenceOf type, or a sequence otherwise
fn Sequence.new_with_tag(tag Tag, seqof bool) !Sequence {
	if !tag.is_constructed() && tag.tag_number() != int(TagType.sequence) {
		return error('Not a valid sequence tag')
	}
	return Sequence{
		tag:   tag
		seqof: seqof
	}
}

pub fn (mut seq Sequence) set_to_sequenceof() ! {
	if !seq.elements.hold_different_tag() {
		seq.seqof = true
		return
	}
	// non-sequenceof, just return error
	return error("Not holds sequenceof elements, you can't set the flag")
}

// is_sequenceof_type checks whether this sequence is SequenceOf type
pub fn (seq Sequence) is_sequenceof_type() bool {
	// we assume the tag is sequence type
	// take the first obj's tag, and check if the all the element tags has the same type
	tag0 := seq.elements[0].tag()
	return seq.elements.all(it.tag() == tag0) && seq.seqof
}

// add_element add the element el to this sequence. Its check whether its should be added when this
// sequence is SequenceOf type
pub fn (mut seq Sequence) add_element(el Element) ! {
	if seq.elements.len == 0 {
		// sequence elements is still empty, just add the element
		seq.elements << el
		return
	}
	// otherwise, sequence elements is not empty, so, lets performs check.
	// get the first element tag, when this sequence is SequenceOf type, to be added element
	// has to be have the same tag with element already availables in sequence.
	tag0 := seq.elements[0].tag()
	if seq.seqof {
		if el.tag() != tag0 {
			return error('Sequence: adding different element to the SequenceOf element')
		}
		// has the same tag
		seq.elements << el
		return
	}
	// otherwise, we can just append el into sequence elements
	seq.elements << el
}

pub fn (s Sequence) elements() ![]Element {
	return s.elements
}

pub fn (s Sequence) tag() Tag {
	return s.tag
}

pub fn (s Sequence) length(p Params) !int {
	mut n := 0
	for e in s.elements {
		n += e.packed_length(p)!
	}
	return n
}

pub fn (s Sequence) payload(p Params) ![]u8 {
	mut out := []u8{}
	for e in s.elements {
		e.encode(mut out, p)!
	}
	return out
}

pub fn (s Sequence) packed_length(p Params) !int {
	mut n := 0
	n += s.tag.packed_length(p)!
	ln := s.length(p)!
	length := Length.from_i64(ln)!
	n += length.packed_length(p)!
	n += ln

	return n
}

pub fn (s Sequence) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Sequence: unsupported mode')
	}
	// recheck
	if !s.tag().is_constructed() && s.tag().tag_number() != int(TagType.sequence) {
		return error('Not a valid sequence tag')
	}
	// pack in DER mode
	s.tag().encode(mut dst, p)!
	payload := s.payload(p)!
	length := Length.from_i64(payload.len)!
	length.encode(mut dst, p)!
	dst << payload
}

pub fn Sequence.decode(src []u8, loc i64, p Params) !(Sequence, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.tag_class() != .universal && !raw.tag.is_constructed()
		&& raw.tag.tag_number() != int(TagType.sequence) {
		return error('Sequence: bad sequence tag')
	}

	mut seq := Sequence.parse_contents(raw.tag, raw.payload)!
	// check for hold_different_tag
	if !seq.elements.hold_different_tag() {
		// set sequence into sequenceof type
		seq.seqof = true
	}
	return seq, next
}

// Utility function
//
fn Sequence.parse_contents(tag Tag, contents []u8, p Params) !Sequence {
	if tag.tag_class() != .universal && !tag.is_constructed()
		&& tag.tag_number() != int(TagType.sequence) {
		return error('Sequence: not sequence tag')
	}

	// by default, we create regular sequence type
	// if you wish SEQUENCE OF type, call `.set_to_sequenceof()`
	// on this seqence to have SEQUENCE OF behavior,
	// or you can call it later.
	mut seq := Sequence.new(false)!
	mut i := i64(0)
	for i < contents.len {
		raw, _ := RawElement.decode(contents, i, p)!
		// t, idx := Tag.decode(contents, i)!
		// ln, next := Length.decode(contents, idx)!
		// TODO: still no check
		sub := raw.payload
		if raw.tag.is_constructed() {
			obj := parse_constructed_element(raw.tag, sub)!
			seq.add_element(obj)!
			i += obj.packed_length(p)!
		} else {
			obj := parse_primitive_element(raw.tag, sub)!
			seq.add_element(obj)!
			i += obj.packed_length(p)!
		}
	}
	return seq
}

fn parse_primitive_element(tag Tag, contents []u8, p Params) !Element {
	if tag.is_constructed() {
		return error('not primitive tag')
	}
	// for other class, just return raw element
	if tag.tag_class() != .universal {
		return RawElement.new(tag, contents)
	}
	// parse as an universal class primitive type
	match tag.tag_number() {
		int(TagType.boolean) {
			return Boolean.from_bytes(contents, p)!
		}
		int(TagType.integer) {
			return Integer.from_bytes(contents, p)!
		}
		int(TagType.bitstring) {
			return BitString.from_bytes(contents, p)!
		}
		int(TagType.octetstring) {
			return OctetString.from_bytes(contents)!
		}
		int(TagType.null) {
			return Null.from_bytes(contents, p)!
		}
		int(TagType.oid) {
			return Oid.from_bytes(contents, p)!
		}
		int(TagType.numericstring) {
			return NumericString.from_bytes(contents, p)!
		}
		int(TagType.printablestring) {
			return PrintableString.from_bytes(contents, p)!
		}
		int(TagType.ia5string) {
			return IA5String.from_bytes(contents, p)!
		}
		int(TagType.generalstring) {
			return GeneralString.from_bytes(contents)!
		}
		int(TagType.utf8string) {
			return UTF8String.from_bytes(contents, p)!
		}
		int(TagType.visiblestring) {
			return VisibleString.from_bytes(contents, p)!
		}
		int(TagType.utctime) {
			return UTCTime.from_bytes(contents, p)!
		}
		int(TagType.generalizedtime) {
			return GeneralizedTime.from_bytes(contents, p)!
		}
		// TODO:
		//   - add other type
		//   - relaxed parsing by return raw asn1 object.
		else {
			return RawElement{
				tag:     tag
				payload: contents
			}
		}
	}
}

fn parse_constructed_element(tag Tag, contents []u8, p Params) !Element {
	if !tag.is_constructed() {
		return error('not constructed tag')
	}
	// Its maybe Explict or Implicit TaggedType, but at here we have no enought
	// information to parse on, so we just return RawElement instead.
	if tag.tag_class() != .universal {
		return RawElement.new(tag, contents)
	}
	// we only parse sequence(of) and or set(of). type
	// for other constructed type, like TaggedType, you should
	// parse manually from RawElement result.
	match tag.tag_number() {
		int(TagType.sequence) {
			return Sequence.parse_contents(tag, contents, p)!
		}
		int(TagType.set) {
			return Set.parse_contents(tag, contents, p)!
		}
		else {
			return RawElement.new(tag, contents)
		}
	}
}

/*
// is_sequenceof_type checks whether the sequence `seq` holds the same elements (its a SEQUENCE OF type).
fn is_sequenceof_type(seq Sequence) bool {
	tag := seq.tag.number
	if tag != int(TagType.sequence) {
		return false
	}
	// take the first obj's tag
	tag0 := seq.elements[0].tag()
	for obj in seq.elements {
		if obj.tag() != tag0 {
			return false
		}
	}
	// return seq.elements.all(it.tag() == tag0)
	return true
}

// new_sequence creates empty universal class of sequence type.
// for other ASN.1 class, see `new_sequence_with_class`
pub fn new_sequence() Sequence {
	seq := new_sequence_with_class(.universal)
	return seq
}

// new_sequence_with_class creates new empty sequence with specific ASN.1 class.
pub fn new_sequence_with_class(c TagClass) Sequence {
	seq := Sequence{
		tag: new_tag(c, true, int(TagType.sequence))
	}
	return seq
}

fn new_sequence_from_multiencoder(me []Encoder) !Sequence {
	mut seq := new_sequence()
	seq.add_multi(me)
	return seq
}

// new_sequence_from_bytes creates new SEQUENCE from bytes
fn new_sequence_from_bytes(src []u8) !Sequence {
	seq := decode_sequence(src)!
	return seq
}

// new_sequenceof_from_bytes creates new SEQUENCEOF from bytes
fn new_sequenceof_from_bytes(src []u8) !Sequence {
	seq := decode_sequence(src)!

	if !is_sequenceof_type(seq) {
		return error('sequence contains some different elements, its not sequenceof')
	}
	return seq
}

pub fn (seq Sequence) length() int {
	mut length := 0
	for obj in seq.elements {
		n := obj.size()
		length += n
	}
	return length
}

pub fn (seq Sequence) size() int {
	mut size := 0

	// calculates tag length
	t := calc_tag_length(seq.tag())
	size += t

	// calculates length of length
	lol := calc_length_of_length(seq.length())
	size += lol

	// length of sequence elements.
	size += seq.length()

	return size
}

pub fn (seq Sequence) encode() ![]u8 {
	mut dst := []u8{}

	serialize_tag(mut dst, seq.tag())
	serialize_length(mut dst, seq.length())

	el := seq.elements.encode()!
	dst << el
	return dst
}

fn (mut seq Sequence) add(obj Encoder) Sequence {
	seq.elements.add(obj)
	return seq
}

fn (mut seq Sequence) add_multi(elements []Encoder) Sequence {
	seq.elements.add_multi(elements)
	return seq
}

fn decode_sequence(src []u8) !Sequence {
	if src.len < 2 {
		return error('invalid minimal length')
	}
	tag, pos := read_tag(src, 0)!
	if !tag.is_sequence_tag() {
		return error('bad tags n look like not a sequence tag=${tag}')
	}

	length, next := decode_length(src, pos)!
	sub := read_bytes(src, next, length)!

	seq := parse_seq(tag, sub)!

	return seq
}

// main routine for parsing sequence
fn parse_seq(tag Tag, contents []u8) !Sequence {
	if !tag.is_sequence_tag() {
		return error('not seq tag')
	}

	mut i := 0
	mut seq := new_sequence_with_class(tag.class)
	for i < contents.len {
		t, idx := read_tag(contents, i)!
		ln, next := decode_length(contents, idx)!

		sub := read_bytes(contents, next, ln)!
		match t.constructed {
			true {
				obj := parse_constructed_element(t, sub)!
				seq.add(obj)
				i += obj.size()
			}
			false {
				obj := parse_primitive_element(t, sub)!
				seq.add(obj)
				i += obj.size()
			}
		}
	}
	return seq
}
*/

module asn1

import io

// Parser is ongoing ASN.1 parser.
// Its capables parsing ASN.1 element through availables methods.
pub struct Parser {
mut:
	data []u8
}

// Parser.new creates a new Parser from bytes array in data.
pub fn Parser.new(data []u8) &Parser {
	return &Parser{
		data: data
	}
}

// reset resets internal data of parser to empty buffer.
pub fn (mut p Parser) reset() {
	p.data = unsafe { p.data[..0] }
}

// peek_tag lookup the tag from the parser without updates internal parser data.
pub fn (mut p Parser) peek_tag() !Tag {
	tag, _ := Tag.from_bytes(p.data)!
	return tag
}

// read_tag lookup the tag from the current parser and updates internal parser data.
pub fn (mut p Parser) read_tag() !Tag {
	tag, rest := Tag.from_bytes(p.data)!
	p.data = rest
	return tag
}

// read_length reads and lookup Length from the current parser.
pub fn (mut p Parser) read_length() !Length {
	length, rest := Length.from_bytes(p.data)!
	p.data = rest
	return length
}

// read_bytes read length bytes from the current parser data.
pub fn (mut p Parser) read_bytes(length int) ![]u8 {
	if length > p.data.len {
		return error('Parser: too short data to read ${length} bytes')
	}
	result := p.data[0..length]
	rest := if length == p.data.len { []u8{} } else { unsafe { p.data[length..] } }
	p.data = rest
	return result
}

// read_element read an element T from the current parser.
// Note: somes builtin have not this method.
pub fn (mut p Parser) read_element[T]() !T {
	return T.parse(mut p)
}

// read_tlv read an Element from the parser data.
// Its return an Element, you should cast it to underlying data if you need.
pub fn (mut p Parser) read_tlv() !Element {
	tag := p.read_tag()!
	length := p.read_length()!
	content := p.read_bytes(length)!

	match tag.class {
		.universal {
			return parse_universal(tag, content)!
		}
		.application {
			return parse_application(tag, content)!
		}
		.context_specific {
			return parse_context_specific(tag, content)!
		}
		.private {
			return parse_private(tag, content)!
		}
	}
}

// finish end this parser or error if not empty.
pub fn (mut p Parser) finish() ! {
	if !p.is_empty() {
		return error('not empty on finish')
	}
}

// is_empty checks whether the parser has empty buffer data.
pub fn (mut p Parser) is_empty() bool {
	return p.data.len == 0
}

// read_from reads up to buf.len bytes from reader r, places them into buf and then appends
// to current Parser data.
pub fn (mut p Parser) read_from(mut r io.Reader, mut buf []u8) !int {
	n := r.read(mut buf)!
	p.data << buf

	return n
}

pub fn parse_single[T](data []u8) !T {
	mut p := Parser.new(data)!
	out := p.read_element[T]()!
	return out
}

fn parse[T](data []u8, callback fn (mut p Parser) !T) !T {
	mut p := Parser.new(data)
	result := callback(mut p)!
	p.finish()!
	return result
}

/*
fn strip_tlv(data []u8) !(Element, []u8) {
	mut p := Parser.new(data)
	tlv := p.read_element[Asn1Element]()!
	return tlv, p.data
}
*/

// type CbParser[T] = fn (T) (mut Parser)() !T
type ConditionFn[T] = fn (mut p Parser) !T

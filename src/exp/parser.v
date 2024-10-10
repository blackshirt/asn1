module asn1

struct Parser {
mut:
	data []u8
}

fn Parser.new(data []u8) &Parser {
	return &Parser{
		data: data
	}
}

fn (mut p Parser) reset() {
	p.data = unsafe { p.data[..0] }
}

pub fn (mut p Parser) peek_tag() !Tag {
	tag, _ := Tag.decode(p.data)!

	return tag
}

pub fn (mut p Parser) read_tag() !Tag {
	tag, next := Tag.decode(p.data)!
	rest := unsafe { p.data[next..] }
	p.data = rest
	return tag
}

fn (mut p Parser) read_length() !Length {
	length, next := Length.decode(p.data)!

	if next > p.data.len {
		return error('too short length data')
	}
	p.data = unsafe { p.data[next..] }
	return length
}

fn (mut p Parser) read_tlv() !Asn1Element {
	tag := p.read_tag()!
	length := p.read_length()!
	data := p.read_bytes(length)!
	return Asn1Element.new(tag, data)!
}

fn (mut p Parser) read_bytes(length int) ![]u8 {
	if length > p.data.len {
		return error('too short data')
	}
	result := p.data[0..length]
	data := p.data[length..]
	p.data = data
	return result
}

fn (mut p Parser) finish() ! {
	if !p.is_empty() {
		return error('not empty on finish')
	}
}

fn (mut p Parser) is_empty() bool {
	return p.data.len == 0
}

pub fn (mut p Parser) read_element[T]() !T {
	return T.parse(mut p)!
}

interface Asn1Parseable {
	can_parse(tag Tag) bool
}

fn Asn1Parseable.parse(mut p Parser) !Asn1Parseable {
	el := p.read_tlv()!
	return el
}

pub fn parse_single[T](data []u8) !T {
	mut p := Parser.new(data)!
	out := p.read_element[T]()!
	return out
}

// type CbParser[T] = fn (T) (mut Parser)() !T
type ConditionFn[T] = fn (mut p Parser) !T

pub fn parse[T](data []u8, cb ConditionFn) !T {
	mut p := Parser.new(data)
	result := cb(mut p)!
	p.finish()!
	return result
}

/// Types with a fixed-tag that can be parsed as DER ASN.1
interface FixedAsn1Parseable {
	tag Tag
	parse_data(data []u8) !FixedAsn1Parseable
}

fn (fp FixedAsn1Parseable) can_parse(tag Tag) bool {
	return fp.tag == tag
}

fn (fp FixedAsn1Parseable) parse(mut p Parser) !Asn1Parseable {
	tlv := p.read_tlv()!
	if !fp.can_parse(tlv.tag()) {
		return error('UnexpectedTag')
	}
	elout := fp.parse_data(tlv.payload()!)!
	return elout as Asn1Parseable
}

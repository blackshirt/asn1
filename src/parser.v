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

// see the tag from the parser without updata parser.data
fn (mut p Parser) peek_tag() !Tag {
	tag, _ := Tag.from_bytes(p.data)!
	return tag
}

fn (mut p Parser) read_tag() !Tag {
	tag, rest := Tag.from_bytes(p.data)!
	p.data = rest
	return tag
}

fn (mut p Parser) read_length() !Length {
	length, rest := Length.from_bytes(p.data)!
	p.data = rest
	return length
}

fn (mut p Parser) read_tlv() !Element {
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
		.contex_specific {
			return parse_context_specific(tag, content)!
		}
		.private {
			return parse_private(tag, content)!
		}
	}
}

fn (mut p Parser) read_bytes(length int) ![]u8 {
	if length > p.data.len {
		return error('Parser: too short data to read ${length} bytes')
	}
	result := p.data[0..length]
	rest := if length == p.data.len { []u8{} } else { unsafe { p.data[length..] } )
	p.data = rest
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

fn (mut p Parser) read_element[T]() !T {
	return T.parse(mut p)
}

pub fn parse_single[T](data []u8) !T {
	mut p := Parser.new(data)!
	out := p.read_element[T]()!
	return out
}

pub fn parse[T](data []u8, callback fn (mut p Parser) !T) !T {
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

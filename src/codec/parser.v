module asn1

struct Parser {
	reader &io.Reader = unsafe { nil }
	data   []u8
}

fn Parser.new(data []u8) &Parser {
	return &Parser{
		data: data
	}
}

fn (mut p Parser) with_reader(reader io.Reader) &Parser {
	p.reader = reader
}

fn (p Parser) finish() ? {
	if !p.is_empty() {
		return none
	}
}

fn (p Parser) is_empty() bool {
	return p.data.len == 0
}

pub fn (p Parser) read_element[T]() !T {
	$if T !is Asn1Readable {
		return error('T is Asn1Readable')
	}
	return T.parse(p)
}

interface Asn1Readable {
	parse(mut parser Parser) !Asn1Readable
	can_parse(tag Tag) bool
}

module main

type Tag = u8

fn Tag.from_bytes(b []u8) !(Tag, []u8) {
	if b.len == 0 {
		return error('empty bytes')
	}
	t := b[0]
	rest := if b.len == 1 { []u8{} } else { b[1..] }
	return t, rest
}

type Length = int

fn Length.from_bytes(b []u8) !(Length, []u8) {
	if b.len == 0 {
		return error('empty bytes')
	}
	length := b[0]
	rest := if b.len == 1 { []u8{} } else { b[1..] }
	return length, rest
}

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

	elem := Raw.new(tag, content)
	return elem
}

fn (mut p Parser) read_bytes(length int) ![]u8 {
	if length > p.data.len {
		return error('too short data')
	}
	result := p.data[0..length]
	rest := unsafe { p.data[length..] }
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

interface Element {
	tag() Tag
	content() ![]u8
}

struct Aa {
	val string
}

fn (a Aa) tag() Tag {
	return Tag(u8(0))
}

fn (a Aa) content() ![]u8 {
	return a.val.bytes()
}

fn Aa.parse(mut p Parser) !Aa {
	tag := p.read_tag()!
	if tag != u8(0) {
		return error('Bad tag')
	}
	length := p.read_length()!
	bytes := p.read_bytes(length)!
	value := Aa.from_bytes(bytes)!

	return value
}

fn Aa.from_bytes(b []u8) !Aa {
	return Aa{
		val: b.bytestr()
	}
}

struct Ab {
	val string
}

fn (b Ab) tag() Tag {
	return Tag(u8(1))
}

fn (b Ab) content() ![]u8 {
	return b.val.bytes()
}

struct Raw {
	tag     Tag
	content []u8
}

fn (r Raw) tag() Tag {
	return r.tag
}

fn (r Raw) content() ![]u8 {
	return r.content
}

fn Raw.new(tag Tag, content []u8) Raw {
	return Raw{
		tag:     tag
		content: content
	}
}

struct Seq {
	fields []Element
}

fn (s Seq) is_seqof[T]() bool {
	// empty fields can be considered as a true, ie, SequenceOf
	return s.fields.all(it is T)
}

fn main() {
	// a := Aa{'aaa'}

	data := [u8(0), u8(3), 0x61, 0x61, 0x61]
	mut p := Parser.new(data)

	// This is fails with the latest V
	out := p.read_element[Aa]()!

	dump(out.val == 'aaa') // true
}

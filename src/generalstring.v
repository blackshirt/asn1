module asn1

// ASN.1 GENERALSTRING Handling
// It may contain any characters from a "G" and "C" set of any standardized character sets.
// A "G" set contains some specified set of graphic (i.e., printable) characters,
// while a "C" set contains a group of control characters.
// For example, the "G" set in the ASCII character set consists of the characters with ASCII numbers 33 through 126,
// while the "C" set is those characters with ASCII numbers 0 through 31.
// For historical reasons, the characters SPACE (number 32) and DELETE (number 127)
// are not considered to be in either the C set or the G set, but instead stand on their own
// We only treated GeneralString as an us-ascii charset
struct GeneralString {
	value string
mut:
	tag Tag = Tag{.universal, false, int(TagType.generalstring)}
}

// TODO: proper check GeneralString validation
fn GeneralString.new(s string) !GeneralString {
	if !s.is_ascii() {
		return error('GeneralString: contains non-ascii chars')
	}
	return GeneralString{
		value: s
	}
}

fn GeneralString.from_bytes(b []u8) !GeneralString {
	if b.any(it < u8(` `) || it > u8(`~`)) {
		return error('GeneralString: bytes contains non-ascii chars')
	}
	return GeneralString{
		value: b.bytestr()
	}
}

fn (g GeneralString) tag() Tag {
	return g.tag
}

fn (g GeneralString) payload(p Params) ![]u8 {
	if !g.value.is_ascii() {
		return error('GeneralString: contains non-ascii chars')
	}
	return g.value.bytes()
}

fn (g GeneralString) length(p Params) int {
	return g.value.bytes().len
}

fn (g GeneralString) packed_length(p Params) int {
	mut n := 0

	n += g.tag().packed_length(p)
	len := Length.from_i64(g.value.bytes().len) or { panic(err) }
	n += len.packed_length(p)
	n += g.value.bytes().len

	return n
}

fn (g GeneralString) pack_to_asn1(mut dst []u8, p Params) ! {
	if !g.value.is_ascii() {
		return error('GeneralString: contains non-ascii char')
	}
	if p.mode != .der && p.mode != .ber {
		return error('GeneralString: unsupported mode')
	}

	g.tag().pack_to_asn1(mut dst, p)!
	bytes := g.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.pack_to_asn1(mut dst, p)!
	dst << bytes
}

fn GeneralString.unpack_from_asn1(src []u8, loc i64, p Params) !(GeneralString, i64) {
	if src.len < 2 {
		return error('GeneralString: bad bytes length')
	}
	if p.mode != .der && p.mode != .ber {
		return error('GeneralString: unsupported mode')
	}
	if loc > src.len {
		return error('GeneralString: bad position offset')
	}

	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	// TODO: checks tag for matching type
	if tag.class() != .universal || tag.is_constructed()
		|| tag.tag_number() != int(TagType.generalstring) {
		return error('GeneralString: bad tag of universal class type')
	}
	// read the length part from current position pos
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// read the bytes part from current position idx to the length part
	// TODO: dont trust provided length, make sure to do checking
	if idx > src.len || idx + len > src.len {
		return error('GeneralString: truncated input')
	}
	// no bytes
	if len == 0 {
		ret := GeneralString{
			tag: tag
		}
		return ret, idx
	}
	bytes := unsafe { src[idx..idx + len] }
	// check for ASCII charset
	if bytes.any(it < u8(` `) || it > u8(`~`)) {
		return error('GeneralString: bytes contains non-ascii chars')
	}
	ret := GeneralString{
		tag: tag
		value: bytes.bytestr()
	}
	return ret, idx + len
}

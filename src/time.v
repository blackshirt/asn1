// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// UTCTime
// -------
// For this time, UTCTime represented by simple string with format "YYMMDDhhmmssZ"
// - the six digits YYMMDD where YY is the two low-order digits of the Christian year,
// (RFC 5280 defines it as a range from 1950 to 2049 for X.509), MM is the month
// (counting January as 01), and DD is the day of the month (01 to 31).
// - the four digits hhmm where hh is hour (00 to 23) and mm is minutes (00 to 59); (SEE NOTE BELOW)
// - the six digits hhmmss where hh and mm are as in above, and ss is seconds (00 to 59);
// - the character Z;
// - one of the characters + or -, followed by hhmm, where hh is hour and mm is minutes (NOT SUPPORTED)
//
// NOTE
// -----
// - Restrictions employed by DER, the encoding shall terminate with "Z".
// - The seconds element shall always be present, and DER (along with RFC 5280) specify that seconds must be present,
// - Fractional seconds must not be present.
//
// TODO:
// - check for invalid representation of date and hhmmss part.
// - represented UTCTime in time.Time
struct UTCTime {
	value string
mut:
	tag Tag = Tag{.universal, false, int(TagType.utctime)}
}

// new_utctime creates new UTCTime from string s.
fn UTCTime.from_string(s string) !UTCTime {
	valid := validate_utctime(s)!
	if !valid {
		return error('UTCTime: fail on validate utctime')
	}
	return UTCTime{
		value: s
	}
}

fn UTCTime.from_bytes(b []u8) !UTCTime {
	return UTCTime.from_string(b.bytestr())!
}

fn (t UTCTime) tag() Tag {
	return t.tag
}

fn (ut UTCTime) packed_length() !int {
	mut n := 0
	n += ut.tag.packed_length()
	len := Length.from_i64(ut.value.bytes().len)!
	n += len.packed_length()

	n += ut.value.bytes().len

	return n
}

fn (t UTCTime) pack_to_asn1(mut dst []u8, p Params) ! {
	valid := validate_utctime(t.value)!
	if !valid {
		return error('UTCTime: fail on validate utctime')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}
	t.tag().pack_to_asn1(mut dst, p)!
	bytes := t.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.pack_to_asn1(mut dst, p)!
	dst << bytes
}

fn UTCTime.unpack_from_asn1(src []u8, loc i64, p Params) !(UTCTime, i64) {
	if src.len < 3 {
		return error('UTCTime: bad len')
	}
	if p.mode != .der && p.mode != .ber {
		return error('UTCTime: unsupported mode')
	}
	if loc > src.len {
		return error('UTCTime: bad position offset')
	}
	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	if tag.class() != .universal || tag.is_constructed() || tag.tag_number() != int(TagType.utctime) {
		return error('UTCTime: bad tag of universal class type')
	}
	// read the length part from current position pos
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	if len == 0 {
		return error('UTCTime: len==0')
	}
	if idx > src.len || idx + len > src.len {
		return error('UTCTime: truncated input')
	}
	// read the bytes part from current position idx to the length part
	bytes := unsafe { src[idx..idx + len] }
	mut ret := UTCTime.from_string(bytes.bytestr())!
	ret.tag = tag
	return ret, idx + len
}

// utility function for UTCTime
//
fn validate_utctime(s string) !bool {
	if !basic_utctime_check(s) {
		return false
	}
	// read contents
	src := s.bytes()
	mut pos := 0
	mut year, mut month, mut day := u16(0), u8(0), u8(0)
	mut hour, mut minute, mut second := u8(0), u8(0), u8(0)

	// UTCTime only encodes times prior to 2050
	year, pos = read_2_digits(src, pos)!
	year = u16(year)
	if year >= 50 {
		year = 1900 + year
	} else {
		year = 2000 + year
	}

	month, pos = read_2_digits(src, pos)!
	day, pos = read_2_digits(src, pos)!

	if !validate_date(year, month, day) {
		return false
	}

	// hhmmss parts
	hour, pos = read_2_digits(src, pos)!
	minute, pos = read_2_digits(src, pos)!
	second, pos = read_2_digits(src, pos)!

	if hour > 23 || minute > 59 || second > 59 {
		return false
	}
	// assert pos == src.len - 1
	if src[pos] != 0x5A {
		return false
	}
	return true
}

fn basic_utctime_check(s string) bool {
	return s.len == 13 && valid_time_contents(s)
}

fn valid_time_contents(s string) bool {
	return s.ends_with('Z') && s.contains_any('0123456789')
}

// GeneralizedTime.
//
// In DER Encoding scheme, GeneralizedTime should :
// - The encoding shall terminate with a "Z"
// - The seconds element shall always be present
// - The fractional-seconds elements, if present, shall omit all trailing zeros;
// - if the elements correspond to 0, they shall be wholly omitted, and the decimal point element also shall be omitted
//
// GeneralizedTime values MUST be:
// - expressed in Greenwich Mean Time (Zulu) and MUST include seconds
// (i.e., times are `YYYYMMDDHHMMSSZ`), even where the number of seconds
// is zero.
// - GeneralizedTime values MUST NOT include fractional seconds.
struct GeneralizedTime {
	value string
mut:
	tag Tag = Tag{.universal, false, int(TagType.generalizedtime)}
}

fn GeneralizedTime.from_string(s string) !GeneralizedTime {
	valid := validate_generalizedtime(s)!
	if !valid {
		return error('GeneralizedTime: failed on validate')
	}
	return GeneralizedTime{
		value: s
	}
}

fn GeneralizedTime.from_bytes(b []u8) !GeneralizedTime {
	return GeneralizedTime.from_string(b.bytestr())!
}

fn (gt GeneralizedTime) tag() Tag {
	return gt.tag
}

fn (gt GeneralizedTime) packed_length() !int {
	mut n := 0
	n += gt.tag.packed_length()
	len := Length.from_i64(gt.value.bytes().len)!
	n += len.packed_length()

	n += gt.value.bytes().len

	return n
}

fn (gt GeneralizedTime) pack_to_asn1(mut dst []u8, p Params) ! {
	valid := validate_generalizedtime(gt.value)!
	if !valid {
		return error('GeneralizedTime: fail on validate')
	}
	if p.mode != .der && p.mode != .ber {
		return error('GeneralizedTime: unsupported mode')
	}

	gt.tag().pack_to_asn1(mut dst, p)!
	bytes := gt.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.pack_to_asn1(mut dst, p)!
	dst << bytes
}

fn GeneralizedTime.unpack_from_asn1(src []u8, loc i64, p Params) !(GeneralizedTime, i64) {
	if src.len < 2 {
		return error('GeneralizedTime: bad payload len')
	}
	if p.mode != .der && p.mode != .ber {
		return error('GeneralizedTime: unsupported mode')
	}
	if loc > src.len {
		return error('GeneralizedTime: bad position offset')
	}
	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	// its only for universal class, maybe present with different context/class
	if tag.class() != .universal || tag.is_constructed()
		|| tag.tag_number() != int(TagType.generalizedtime) {
		return error('GeneralizedTime: bad tag of universal class type')
	}
	// read the length part from current position pos
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	if len == 0 {
		// we dont allow null length
		return error('GeneralizedTime: len==0')
	}
	if idx > src.len || idx + len > src.len {
		return error('GeneralizedTime: truncated input')
	}
	// read the bytes part from current position idx to the length part
	// internally, .from_string performs validation part
	bytes := unsafe { src[idx..idx + len] }
	mut ret := GeneralizedTime.from_string(bytes.bytestr())!
	ret.tag = tag
	return ret, idx + len
}

// utility function for GeneralizedTime
// TODO: more clear and concise validation check
fn min_generalizedtime_length(s string) bool {
	// minimum length without fractional element
	return s.len >= 15
}

fn generalizedtime_contains_fraction(s string) bool {
	// contains '.' part
	return s.contains('.')
}

fn basic_generalizedtime_check(s string) bool {
	return min_generalizedtime_length(s) && valid_time_contents(s)
}

fn validate_generalizedtime(s string) !bool {
	if !basic_generalizedtime_check(s) {
		return false
	}
	// read contents
	src := s.bytes()
	mut pos := 0
	mut year, mut month, mut day := u16(0), u8(0), u8(0)
	mut hour, mut minute, mut second := u8(0), u8(0), u8(0)

	// Generalized time format was "YYYYMMDDhhmmssZ"
	// TODO: support for second fractions part
	year, pos = read_4_digits(src, pos)!
	// year = u16(year)
	month, pos = read_2_digits(src, pos)!
	day, pos = read_2_digits(src, pos)!

	if !validate_date(year, month, day) {
		return false
	}

	// hhmmss parts
	hour, pos = read_2_digits(src, pos)!
	minute, pos = read_2_digits(src, pos)!
	second, pos = read_2_digits(src, pos)!

	if hour > 23 || minute > 59 || second > 59 {
		return false
	}
	// assert pos == src.len - 1
	if src[pos] != 0x5A {
		return false
	}
	return true
}

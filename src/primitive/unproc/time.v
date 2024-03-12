// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

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
	tag asn.Tag = asn1.Tag{.universal, false, int(asn1.TagType.utctime)}
}

// new_utctime creates new UTCTime from string s.
fn UTCTime.from_string(s string) !UTCTime {
	if !validate_utctime(s) {
		return error('UTCTime: fail on validate utctime')
	}
	return UTCTime{
		value: s
	}
}

fn (t UTCTime) tag() asn1.Tag {
	return t.tag
}

fn (t UTCTime) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	if !validate_utctime(t) {
		return error('UTCTime: fail on validate utctime')
	}
	match mode {
		.ber, .der {
			t.tag().pack_to_asn1(mut to, mode, p)!
			bytes := t.value.bytes()
			length := asn1.Length.from_i64(bytes.len)!
			length.pack_to_asn1(mut to, mode, p)!
			to << bytes
		}
		else {
			return error('Unsupported')
		}
	}
}

fn UTCTime.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(UTCTime, i64) {
	if b.len < 2 {
		return error('UTCTime: bad len')
	}
	match mode {
		.ber, .der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, .der, p)!
			if tag.class() != .universal || tag.is_compound()
				|| tag.tag_number() != int(asn1.TagType.utctime) {
				return error('UTCTime: bad tag of universal class type')
			}
			// read the length part from current position pos
			len, idx := asn1.Length.unpack_from_asn1(b, pos, .der, p)!
			if len == 0 {
				return error('UTCTime: len==0')
			}
			if idx + len > b.len {
				return error('UTCTime: truncated input')
			}
			// read the bytes part from current position idx to the length part
			bytes := unsafe { b[idx..idx + len] }
			// buf := trim_bytes(bytes)!
			ret := UTCTime.from_string(bytes.bytestr())!
			return ret, idx + len
		}
		else {
			return error('Unsupported')
		}
	}
}

fn serialize_utctime(s string) ![]u8 {
	valid := validate_utctime(s)!
	if !valid {
		return error('fail on validate utctime')
	}
	p := s.bytes()
	t := new_tag(.universal, false, int(TagType.utctime))
	mut out := []u8{}

	serialize_tag(mut out, t)
	serialize_length(mut out, p.len)
	out << p
	return out
}

fn decode_utctime(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode utctime: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	// check tag is matching utctime tag
	if tag.number != int(TagType.utctime) {
		return error('bad tag detected')
	}
	if pos > src.len {
		return error('truncated input')
	}

	// mut length := 0
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!

	str := out.bytestr()
	valid := validate_utctime(str)!
	if !valid {
		return error('invalid utctime string')
	}

	return tag, str
}

// utility function
//
fn validate_utctime(s string) bool {
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
pub type GeneralizedTime = string

pub fn new_generalizedtime(s string) !Encoder {
	valid := validate_generalizedtime(s)!
	if !valid {
		return error('fail on validate generalizedtime')
	}
	return GeneralizedTime(s)
}

pub fn (gt GeneralizedTime) tag() Tag {
	return new_tag(.universal, false, int(TagType.generalizedtime))
}

pub fn (gt GeneralizedTime) length() int {
	return gt.len
}

pub fn (gt GeneralizedTime) size() int {
	mut size := 0
	tag := gt.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length(gt.length())
	size += int(l)

	size += gt.length()

	return size
}

pub fn (gt GeneralizedTime) encode() ![]u8 {
	return serialize_generalizedtime(gt)
}

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
		return error('fail basic generalizedtime check')
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

fn serialize_generalizedtime(s string) ![]u8 {
	valid := validate_generalizedtime(s)!
	if !valid {
		return error('fail on validate utctime')
	}
	p := s.bytes()
	t := new_tag(.universal, false, int(TagType.generalizedtime))
	mut out := []u8{}

	serialize_tag(mut out, t)
	serialize_length(mut out, p.len)
	out << p
	return out
}

fn decode_generalizedtime(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode utctime: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	// check tag is matching
	if tag.number != int(TagType.generalizedtime) {
		return error('bad tag detected')
	}
	if pos > src.len {
		return error('truncated input')
	}

	// mut length := 0
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!

	str := out.bytestr()
	valid := validate_generalizedtime(str)!
	if !valid {
		return error('invalid generalizedtime string')
	}
	return tag, str
}

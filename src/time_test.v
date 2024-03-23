// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

fn test_serialize_utctime_basic() ! {
	inp := '191215190210Z'

	exp := [u8(0x17), 0x0D, 49, 57, 49, 50, 49, 53, 49, 57, 48, 50, 49, 48, 90]

	ut := UTCTime.from_string(inp)!
	mut out := []u8{}
	ut.encode(mut out, .der)!

	assert out == exp

	// back
	back, pos := UTCTime.decode(out, 0, .der)!
	assert back.tag.tag_number() == int(asn1.TagType.utctime)
	assert back == ut
	assert back.value == inp
}

fn test_serialize_utctime_error_without_z() ! {
	// this input does not contains zulu 'Z' part
	inp := '191215190210'

	exp := [u8(0x17), 0x0D, 49, 57, 49, 50, 49, 53, 49, 57, 48, 50, 49, 48]

	ut := UTCTime.from_string(inp) or {
		assert err == error('UTCTime: fail on validate utctime')
		return
	}
}

fn test_serialize_utctime_error_month() ! {
	// the month part is > 12
	inp := '191815190210Z'

	exp := [u8(0x17), 0x0D, 49, 57, 49, 56, 49, 53, 49, 57, 48, 50, 49, 48]

	ut := UTCTime.from_string(inp) or {
		assert err == error('UTCTime: fail on validate utctime')
		return
	}
}

fn test_serialize_utctime_error_day() ! {
	// the day part is > 30
	inp := '191235190210Z'

	exp := [u8(0x17), 0x0D, 0x31, 0x39, 0x31, 0x32, 0x31, 0x32, 0x31, 0x39, 0x30, 0x32, 0x31, 0x30,
		0x5A]

	ut := UTCTime.from_string(inp) or {
		assert err == error('UTCTime: fail on validate utctime')
		return
	}
}

fn test_serialize_decode_generalizedtime() ! {
	s := '20100102030405Z'

	exp := [u8(0x18), 0x0f, 50, 48, 49, 48, 48, 49, 48, 50, 48, 51, 48, 52, 48, 53, 90]

	gt := GeneralizedTime.from_string(s)!
	mut out := []u8{}
	gt.encode(mut out, .der)!
	assert out == exp

	// back
	back, pos := GeneralizedTime.decode(out, 0, .der)!

	assert back == gt
	assert back.value == s
	assert back.tag.tag_number() == int(asn1.TagType.generalizedtime)
}

/*
fn test_sequence_of_time() ! {
	mut seq := new_sequence()

	o1 := new_boolean(true) // 3
	o2 := new_utctime('191215190210Z')! // 15
	o3 := new_boolean(false) // 3
	o4 := new_generalizedtime('20100102030405Z')! // 17

	seq.add(o1)
	seq.add(o2)
	seq.add(o3)
	seq.add(o4)

	assert seq.length() == 3 + 15 + 3 + 17 // 38
	assert seq.size() == 2 + 38

	out := seq.encode()!
	exp := [u8(0x30), 38, u8(0x01), 0x01, 0xff, u8(0x17), 0x0D, 49, 57, 49, 50, 49, 53, 49, 57,
		48, 50, 49, 48, 90, u8(0x01), 0x01, 0x00, u8(0x18), 0x0f, 50, 48, 49, 48, 48, 49, 48, 50,
		48, 51, 48, 52, 48, 53, 90]

	assert out == exp
}
*/

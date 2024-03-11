// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn test_serialize_utctime_basic() ! {
	inp := '191215190210Z'

	exp := [u8(0x17), 0x0D, 49, 57, 49, 50, 49, 53, 49, 57, 48, 50, 49, 48, 90]

	out := serialize_utctime(inp)!

	assert out == exp

	// back
	tag, back := decode_utctime(out)!
	assert tag.number == int(TagType.utctime)
	assert back == inp
}

fn test_serialize_utctime_error_z() ! {
	// this input does not contains zulu 'Z' part
	inp := '191215190210'

	exp := [u8(0x17), 0x0D, 49, 57, 49, 50, 49, 53, 49, 57, 48, 50, 49, 48]

	_ := serialize_utctime(inp) or {
		assert err == error('fail basic utctime check')
		return
	}
}

fn test_serialize_utctime_error_month() ! {
	// this input does not contains zulu 'Z' part
	inp := '191815190210Z'

	exp := [u8(0x17), 0x0D, 49, 57, 49, 56, 49, 53, 49, 57, 48, 50, 49, 48]

	_ := serialize_utctime(inp) or {
		assert err == error('fail on validate utctime')
		return
	}
}

fn test_serialize_utctime_error_day() ! {
	// this input does not contains zulu 'Z' part
	inp := '191235190210Z'

	exp := [u8(0x17), 0x0D, 0x31, 0x39, 0x31, 0x32, 0x31, 0x32, 0x31, 0x39, 0x30, 0x32, 0x31, 0x30,
		0x5A]

	out := serialize_utctime(inp) or {
		assert err == error('fail on validate utctime')
		return
	}

	assert out == exp
}

fn test_serialize_decode_generalizedtime() ! {
	s := '20100102030405Z'

	exp := [u8(0x18), 0x0f, 50, 48, 49, 48, 48, 49, 48, 50, 48, 51, 48, 52, 48, 53, 90]

	out := serialize_generalizedtime(s)!
	assert out == exp

	// back
	tag, str := decode_generalizedtime(out)!

	assert s == str
	assert tag.number == int(TagType.generalizedtime)
}

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

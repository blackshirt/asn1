// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import asn1

// VisibleString
struct VisibleTest {
	inp string
	out []u8
	err IError
}

fn test_visible_string_handling() {
	vb := [
		VisibleTest{'', [u8(26), 0], none},
		VisibleTest{'abc', [u8(26), 0x03, 97, 98, 99], none},
		VisibleTest{'abc\x1A', [u8(26), 0x03, 97, 98, 99, 26], error('contains invalid (control) char')},
		VisibleTest{'abc\x5A', [u8(26), 0x04, 97, 98, 99, 0x5a], none},
	]

	for c in vb {
		vs := VisibleString.from_string(c.inp)!
		mut out := []u8{}
		vs.pack_to_asn1(mut out, .der) or {
			assert err == c.err
			continue
		}

		assert out == c.out

		// back
		vsback, idx := VisibleString.unpack_from_asn1(out, 0, .der)!

		assert vsback.tag.tag_number() == int(asn1.TagType.visiblestring)
		assert vsback.value == c.inp
	}
}

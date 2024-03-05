// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn test_sort_the_set() {
	mut objs := []Encoder{}

	val12 := new_integer(AsnInteger(12))
	val32 := new_integer(AsnInteger(32))
	valbol := new_boolean(false)
	valnull := new_null()
	valapp := new_asn_object(.application, false, 34, [u8(44), 45])
	valctx := new_asn_object(.context, false, 35, [u8(50), 55])

	objs << val12 // tag: 2
	objs << val32 // tag: 2
	objs << valctx //
	objs << valapp //
	objs << valbol // tag: 1
	objs << valnull // tag: 5

	awal := objs.clone()

	objs.sort_the_set()
	// dump(objs)
	exp := [valbol, val12, val32, valnull, valapp, valctx]
	assert awal != objs
	assert objs == exp
}

fn test_sort_the_setof() ! {
	mut objs := []Encoder{}

	val1 := new_integer(AsnInteger(1))
	val2 := new_integer(AsnInteger(12))
	val3 := new_integer(AsnInteger(323))
	val4 := new_integer(AsnInteger(4325))
	val5 := new_integer(AsnInteger(44446))
	val0 := new_integer(AsnInteger(0))
	val6 := new_boolean(false)

	// randomly added to array
	objs << val4 // tag: 2
	objs << val2 // tag: 2
	objs << val5 // tag: 2
	objs << val1 // tag: 2
	objs << val3 // tag: 2
	objs << val0 // tag: 2

	awal := objs.clone()
	awalexp := [val4, val2, val5, val1, val3, val0]
	assert awal == awalexp
	// dump(objs)

	objs.sort_the_setof()!

	// dump(objs)
	exp := [val0, val1, val2, val3, val4, val5]
	assert awal != objs
	assert objs == exp
}

fn test_set_encode() ! {
	mut set1 := new_set()

	set1.add_multi([new_boolean(false), new_null(), new_integer(4)])
	// boolean tag:1 length: 3, integer tag:2 length: 3, null tag: 5 length: 2, total length: 8
	// so, it should sort to
	// [boolean, integer, null]
	exp := [u8(0x31), 8, 1, 1, 0, 2, 1, 4, 5, 0]
	out := set1.encode()!

	assert out == exp

	back := der_decode(exp)!

	assert out == back.encode()!
}

fn test_setof_encode() ! {
	mut set1 := Set{
		tag: new_tag(.universal, true, int(TagType.set))
	}

	set1.add_multi([new_integer(55), new_integer(4), new_integer(666)])
	// 666 serialized to [2, 154]
	// encoded sort: [int1, int2, int3]
	exp := [u8(0x31), 10, 2, 1, 4, 2, 1, 55, 2, 2, 2, 0x9a]
	out := set1.encode()!

	assert out == exp

	back := der_decode(exp)!
	if back is Set {
		// set is only sorted on encode() step, so
		assert back != set1
		// create new set of with sorted objects
		objs := [new_integer(4), new_integer(55), new_integer(666)]
		mut set2 := new_set()
		set2.add_multi(objs)

		assert back == set2
	}
}

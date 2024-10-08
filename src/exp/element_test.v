module asn1

type MyOct = string

fn (mo MyOct) tag() Tag {
	return Tag{.universal, false, u32(int(TagType.octetstring))} // 0x04
}

fn (mo MyOct) payload() ![]u8 {
	return mo.bytes()
}

type MyStr = string

fn (ms MyStr) tag() Tag {
	return Tag{.universal, false, u32(int(TagType.utf8string))} // 0x12
}

fn (ms MyStr) payload() ![]u8 {
	return ms.bytes()
}

struct TestStruct {
	n int
	a MyOct
	b MyStr
}

fn (t TestStruct) tag() Tag {
	return Tag{.universal, true, u32(int(TagType.sequence))} // 0x30
}

fn (t TestStruct) payload() ![]u8 {
	kd := KeyDefault(map[string]Element{})
	out := build_payload[TestStruct](t, kd)!
	return out
}

fn test_struct_build_payload() ! {
	st := TestStruct{
		a: MyOct('aku')
		b: MyStr('dia')
	}
	// TestStruct is sequence
	out := encode(st)!
	expected := [u8(0x30), 0x0a, (0x04), 0x03, 0x61, 0x6b, 0x75, (0x0c), 0x03, 0x64, 0x69, 0x61]
	// without field option passed, its should be expected value
	assert out == expected
}

fn test_into_optional() ! {
	// boolean raw, id = 1
	el := RawElement{
		tag:     Tag.new(.universal, false, int(TagType.boolean))!
		payload: [u8(0xff)]
	}
	orig_exp := [u8(0x01), 0x01, 0xff]

	without_option := encode(el)!
	assert without_option == orig_exp

	// marked this element as optional, make its serialized into empty bytes
	with_option_1 := encode_with_options(el, 'optional')!
	assert with_option_1 == []u8{}

	// the same meaning with above 'optional'
	with_option_2 := encode_with_options(el, 'optional:false')!
	assert with_option_2 == []u8{}

	// presences of true flag tells this optional to be serializable
	with_option_3 := encode_with_options(el, 'optional:true')!
	assert with_option_3 == orig_exp
}

// test for wrapping functionality
struct WrapperTest {
	attr string
	err  IError
	out  []u8
}

fn test_wrapping_functionality() ! {
	// raw boolean element
	elem := RawElement{
		tag:     Tag.new(.universal, false, int(TagType.boolean))!
		payload: [u8(0xff)]
	}
	orig_exp := [u8(0x01), 0x01, 0xff]
	data := [
		WrapperTest{'', none, orig_exp},
		// Tag{.contex_specific, true, 1} = 0b1010_0001
		WrapperTest{'context_specific:1; mode:explicit', none, [u8(0xa1), 0x03, 0x01, 0x01, 0xff]},
		WrapperTest{'context_specific:1; mode:implicit; inner:1', none, [u8(0xa1), 0x01, 0xff]},
		// inner is not make sense when encoding
		WrapperTest{'context_specific:1;mode:implicit;inner:2', none, [u8(0xa1), 0x01, 0xff]},
		// empty mode treated as an explicit
		WrapperTest{'application:5', none, [u8(0x65), 0x03, 0x01, 0x01, 0xff]},
		// marked as optional would not be encoded
		WrapperTest{'application:5; optional', none, []u8{}},
		WrapperTest{'application:5', none, [u8(0x65), 0x03, 0x01, 0x01, 0xff]},
		// wrapped into universal is error
		WrapperTest{'universal:50', error('wraps into same class is not allowed'), orig_exp},
		// marked as an optional
		WrapperTest{'private:10; optional', none, []u8{}},
		WrapperTest{'application:5;mode:implicit', error('inner tag number was not set in implicit mode'), []u8{}},
		WrapperTest{'application:5; mode:implicit; inner:1', none, [u8(0x65), 0x01, 0xff]},
	]
	for i, item in data {
		out := encode_with_options(elem, item.attr) or {
			assert item.err == err
			continue
		}
		assert out == item.out
	}
}

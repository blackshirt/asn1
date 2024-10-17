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
	out := make_payload[TestStruct](t, kd)!
	return out
}

fn test_struct_make_payload() ! {
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
	el := Boolean.new(true)
	orig_expected := [u8(0x01), 0x01, 0xff]

	without_option := encode(el)!
	assert without_option == orig_expected

	// marked this element as optional, make its serialized into empty bytes
	with_option_1 := encode_with_options(el, 'optional')!
	///assert with_option_1 == []u8{}

	// the same meaning with above 'optional'
	with_option_2 := encode_with_options(el, 'optional:false')!
	assert with_option_2 == []u8{}

	// presences of true flag tells this optional to be serializable
	with_option_3 := encode_with_options(el, 'optional:true')!
	assert with_option_3 == orig_expected

	options_4 := FieldOptions.from_string('optional:true')!
	with_option_4 := encode_with_field_options(el, options_4)!
	assert with_option_4 == orig_expected
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
		content: [u8(0xff)]
	}
	orig_expected := [u8(0x01), 0x01, 0xff]
	data := [
		WrapperTest{'', none, orig_expected},
		// Tag{.contex_specific, true, 1} = 0b1010_0001
		WrapperTest{'context_specific:1; mode:explicit', error('inner value is not set in wrapped mode'), [
			u8(0xa1),
			0x03,
			0x01,
			0x01,
			0xff,
		]},
		WrapperTest{'context_specific:1; mode:implicit; inner:universal,false,1', none, [
			u8(0xa1),
			0x01,
			0xff,
		]},
		// inner is not make sense when encoding
		WrapperTest{'context_specific:1;mode:implicit;inner:universal, false, 2', none, [
			u8(0xa1),
			0x01,
			0xff,
		]},
		// empty mode treated as an explicit, without inner would an error
		WrapperTest{'application:5', error('inner value is not set in wrapped mode'), [
			u8(0x65),
			0x03,
			0x01,
			0x01,
			0xff,
		]},
		// marked as optional would not be encoded,
		WrapperTest{'application:5; optional;inner:universal,false,2', none, []u8{}},
		WrapperTest{'application:5; inner:universal,false,2', none, [
			u8(0x65),
			0x03,
			0x01,
			0x01,
			0xff,
		]},
		// wrapped into universal is error
		WrapperTest{'universal:50;inner:universal,false,3', error('wraps into same class is not allowed'), orig_expected},
		// marked as an optional
		WrapperTest{'private:10; optional', error('inner value is not set in wrapped mode'), []u8{}},
		WrapperTest{'application:5;mode:implicit', error('inner value is not set in wrapped mode'), []u8{}},
		WrapperTest{'application:5; mode:implicit; inner:universal, false, 1', none, [
			u8(0x65),
			0x01,
			0xff,
		]},
	]
	for i, item in data {
		out := encode_with_options(elem, item.attr) or {
			assert item.err == err
			continue
		}
		assert out == item.out
	}
}

// test for ElementList
fn test_for_element_list() ! {
	mut fields := ElementList([]Element{})

	a := Boolean.new(true)
	b := Boolean.new(false)

	fields << a
	fields << b

	fields_payload := fields.payload()!

	expected := [u8(0x01), 0x01, 0xff, u8(0x01), 1, 0]
	assert fields_payload == expected
	assert fields.encoded_len() == 6

	els := ElementList.from_bytes(expected)!
	assert els.len == 2
	assert els[0] is Boolean
	assert els[1] is Boolean
}

module asn1

@[heap]
struct StringOption {
	src         string
	err         IError
	cls         string
	num         int
	optional    bool
	has_default bool
	mode        string
	present     bool
}

fn test_parse_string_option() ! {
	data := [
		StringOption{'application:20;mode:explicit', none, 'application', 20, false, false, 'explicit', false},
		StringOption{'private:0x20;mode:implicit', none, 'private', 32, false, false, 'implicit', false},
		StringOption{'application:20', error(' `bad mode marker`'), 'application', 20, false, false, '', false},
		StringOption{'private:0x20', error(' `bad mode marker`'), 'private', 32, false, false, '', false},
		StringOption{'context_specific:0x20; optional; has_default; mode:explicit', none, 'context_specific', 32, true, true, 'explicit', false},
		StringOption{'context_specific:0x20; optional; has_default; mode:implicit', none, 'context_specific', 32, true, true, 'implicit', false},
		StringOption{'application:5; optional', none, 'application', 5, true, false, '', false},
	]
	for item in data {
		fo := FieldOptions.from_string(item.src) or {
			assert err == item.err
			continue
		}
		assert fo.cls == item.cls
		assert fo.tagnum == item.num
		assert fo.optional == item.optional
		assert fo.has_default == item.has_default
		assert fo.mode.str() == item.mode
	}
}

struct OptionalMarker {
	attr    string
	present bool
	err     IError
}

fn test_optional_marker_parsing() ! {
	data := [
		// exactly matching key
		OptionalMarker{'optional', false, none},
		// matching key contains spaces is allowed
		OptionalMarker{'optional ', false, none},
		OptionalMarker{'      optional ', false, none},
		// optional with present flag
		OptionalMarker{'optional: true ', true, none},
		OptionalMarker{'optional: false ', false, none},
		// this should not allowed
		OptionalMarker{'', false, error('not optional marker')},
		// need the present value should be set
		OptionalMarker{'optional:', false, error('bad optional value')},
		OptionalMarker{'optional:dd', false, error('bad optional value')},
		OptionalMarker{'optional_aaa', false, error('bad optional key')},
		OptionalMarker{'opt', false, error('not optional marker')},
		// present flag is set but not valid one
		OptionalMarker{'optional: trueorfalse ', false, error('bad optional value')},
		// multiples values is not allowed
		OptionalMarker{'optional: true:false ', false, error('bad optional marker length')},
		OptionalMarker{'optional: true ', true, none},
	]
	for item in data {
		res, status := parse_optional_marker(item.attr) or {
			assert err == item.err
			continue
		}
		assert valid_optional_key(res) == true
		present := if status == 'true' { true } else { false }
		assert present == item.present
	}
}

struct TagMarker {
	attr string
	cls  string
	num  int
	err  IError
}

fn test_tag_marker_parsing() ! {
	data := [
		// normal
		TagMarker{'application:100', 'application', 100, none},
		TagMarker{'context_specific:100', 'context_specific', 100, none},
		// normal with hex number
		TagMarker{'private:0x54', 'private', 0x54, none},
		TagMarker{'universal:0x5f', 'universal', 0x5f, none},
		// normal with spaces should be allowed
		TagMarker{'application: 0x20', 'application', 0x20, none},
		TagMarker{'    application   : 0x20    ', 'application', 0x20, none},
		// bad tag key should error
		TagMarker{'embuh: 0x20', '', 0x20, error('not a tag marker')},
		TagMarker{'private_embuh: 0x20', '', 0x20, error('bad tag name')},
		// key without number also error
		TagMarker{'private_embuh', '', 0, error('bad tag marker length')},
		TagMarker{'private:', 'private', 0, error('bad tag number')},
		TagMarker{'private:bb', 'private', 0, error('bad tag number')},
	]
	for item in data {
		k, v := parse_tag_marker(item.attr) or {
			assert err == item.err
			continue
		}
		assert k == item.cls
		assert v.int() == item.num
	}
}

struct HasDefaultMarker {
	attr string
	err  IError
}

fn test_has_default_marker_parsing() ! {
	data := [
		HasDefaultMarker{'has_default', none},
		HasDefaultMarker{'  has_default  ', none},
		HasDefaultMarker{'', error('not has_default marker')},
		HasDefaultMarker{'has_default:', error('bad has_default marker')},
		HasDefaultMarker{'has_defaultaa', error('bad has_default marker')},
	]
	for item in data {
		s := parse_default_marker(item.attr) or {
			assert err == item.err
			continue
		}
		assert valid_default_marker(s) == true
	}
}

struct TaggedModeMarker {
	attr  string
	value string
	err   IError
}

fn test_mode_marker_parsing() ! {
	data := [
		// the normal right thing
		TaggedModeMarker{'mode:explicit', 'explicit', none},
		TaggedModeMarker{'mode:implicit', 'implicit', none},
		// with spaces is allowed
		TaggedModeMarker{'   mode  : implicit ', 'implicit', none},
		// bad key or value
		TaggedModeMarker{'model:implicit', '', error('bad mode key')},
		TaggedModeMarker{'mode:implicitkey', '', error('bad mode value')},
		TaggedModeMarker{'modelimplicit', '', error('bad mode marker')},
	]
	for i, item in data {
		// dump(i)
		k, v := parse_mode_marker(item.attr) or {
			assert err == item.err
			continue
		}
		assert valid_mode_key(k) == true
		assert v == item.value
	}
}

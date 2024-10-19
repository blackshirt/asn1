module asn1

struct StringOption {
	src         string
	cls         string
	tagnum      int
	mode        string
	inner		int 
	optional    bool
	has_default bool
	err         IError
}

fn test_parse_string_option() ! {
	data := [
		// should parseable
		StringOption{'application:20;explicit;inner:5', 'application', 20, 'explicit', 5. false, false, none},
		StringOption{'private:0x20;implicit;inner:5', 'private', 32, 'implicit', 5, false, false, none},
		StringOption{'context_specific:0x20;implicit;inner:5', 'context_specific', 32, 'implicit', 5, false, false, none},
		StringOption{'private:0x20;implicit;inner:5; optional', 'private', 32, 'implicit', 5, true, false, none},
		StringOption{'private:0x20;implicit;inner:5; has_default', 'private', 32, 'implicit', 5, false, true, none},
		StringOption{'private:0x20;implicit;inner:5; optional; has_default', 'private', 32, 'implicit', 5, true, true, none},
		// not parseable
		StringOption{'application:20', 'application', 20, false, false, '', false, error(' `bad mode marker`')},
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

struct ModeMarker {
	attr  string
	value string
	err   IError
}

fn test_mode_marker_parsing() ! {
	data := [
		// the normal right thing
		ModeMarker{'explicit', 'explicit', none},
		ModeMarker{'implicit', 'implicit', none},
		// with spaces is allowed
		ModeMarker{'    implicit ', 'implicit', none},
		ModeMarker{'    explicit    ', 'implicit', none},
		// bad key or value
		ModeMarker{'xx_implicit', '', error('bad mode key')},
		ModeMarker{'implicitkey', '', error('bad mode value')},
		ModeMarker{'exoplicit implicit', '', error('bad mode marker')},
	]
	for i, item in data {
		// dump(i)
		v := parse_mode_marker(item.attr) or {
			assert err == item.err
			continue
		}
		assert valid_mode_key(v) == true
		assert v == item.value
	}
}

struct InnerMarker {
	src		string 
	result 	int 
	err 	IError
}

fn test_for_inner_tag_marker() ! {
	data := [InnerMarker{'',0,none}, InnerMarker{'inner:0', 0, none}]
	for item in data {
		k, v := parse_inner_tag_marker(item) or {
			assert err == item.err 
			continue
		}
		assert v == item.result 
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

struct OptionalMarker {
	attr    string
	valid 	bool 
	err     IError
}

fn test_optional_marker_parsing() ! {
	data := [
		// exactly matching key
		OptionalMarker{'optional', true, none},
		// matching key contains spaces is allowed
		OptionalMarker{'optional ', true, none},
		OptionalMarker{'      optional ', true, none},
		
		// contains another key is not allowed
		OptionalMarker{'optional: true ', false, none},
		OptionalMarker{'optional-- ', false, none},
		// this should not allowed
		OptionalMarker{'', false, error('not optional marker')},
		OptionalMarker{'optional_aaa', false, error('bad optional key')},
		OptionalMarker{'opt', false, error('not optional marker')},
		OptionalMarker{'xx_optional_ ', false, error('bad optional value')},
	]
	for item in data {
		res := parse_optional_marker(item.attr) or {
			assert err == item.err
			continue
		}
		assert valid_optional_key(res) == true
	}
}


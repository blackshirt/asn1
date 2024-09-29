module asn1

@[heap]
struct StringOption {
	src         string
	err         IError
	cls         TagClass
	num         int
	optional    bool
	has_default bool
	mode        string
}

fn test_parse_string_option() ! {
	data := [
		StringOption{'application:20', none, TagClass.from_string('application')!, 20, false, false, ''},
		StringOption{'private:0x20', none, TagClass.from_string('private')!, 32, false, false, ''},
		StringOption{'context_specific:0x20;optional;has_default;mode:explicit', none, TagClass.from_string('context_specific')!, 32, true, true, 'explicit'},
	]
	for item in data {
		fo := parse_string_option(item.src) or {
			assert err == item.err
			continue
		}
		assert *fo.wrapper == item.cls
		assert *fo.tagnum == item.num
		assert fo.optional == item.optional
		assert fo.has_default == item.has_default
		assert fo.mode.str() == item.mode
	}
}

struct OptionalMarker {
	attr string
	err  IError
}

fn test_optional_marker_parsing() ! {
	data := [
		// exactly matching key
		OptionalMarker{'optional', none},
		// matching key contains spaces is allowed
		OptionalMarker{'optional ', none},
		OptionalMarker{'      optional ', none},
		// this should not allowed
		OptionalMarker{'', error('not optional marker')},
		OptionalMarker{'optional:', error('bad optional marker')},
		OptionalMarker{'optional:dd', error('bad optional marker')},
		OptionalMarker{'optional_aaa', error('bad optional marker')},
		OptionalMarker{'opt', error('not optional marker')},
	]
	for item in data {
		res := parse_optional_marker(item.attr) or {
			assert err == item.err
			continue
		}
		assert valid_optional_marker(res) == true
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
		TaggedModeMarker{'mode:explicit', 'explicit', none},
		TaggedModeMarker{'mode:implicit', 'implicit', none},
		TaggedModeMarker{'   mode  : implicit ', 'implicit', none},
		TaggedModeMarker{'model:implicit', '', error('bad mode key')},
		TaggedModeMarker{'mode:implicitkey', '', error('bad mode value')},
		TaggedModeMarker{'modelimplicit', '', error('bad mode marker')},
	]
	for item in data {
		k, v := parse_mode_marker(item.attr) or {
			assert err == item.err
			continue
		}
		assert valid_mode_key(k) == true
		assert v == item.value
	}
}

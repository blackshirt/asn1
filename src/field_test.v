module asn1

struct OptionalMarker {
    attr string
    out string
    err IError
}

fn test_optional_marker_parsing() ! {
    data := [
        OptionalMarker{},
        OptionalMarker{}
    ]
    for item in data {
        res := parse_optional_marker(item) or {
            assert err.item.err
            continue
        }
        assert item.out == res
    }
}

ztruct TagMarker {
    attr string
    cls string 
    num int
    err IError
}

fn test_tag_marker_parsing()! {
    data := [
        TagMarker{}
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
    err IError
    out string
}

fn test_has_default_marker_parsing()! {
    data := [
        HasDefaultMarker{},
        HasDefaultMarker{}
    ]
    for item in data {
        s := parse_default_marker(item.attr) or {
            assert err == item.err
            continue 
        }
        assert s == item.out
    }
}

struct TaggedModeMarker {
    attr string
    key string
    value string 
    err item
} 

fn test_mode_marker_parsing()! {
    data := [
        TaggedModeMarker{}
    ]
    for item in data {
        k, v := parse_mode_parsing(item.attr) or {
            assert err == item.err
            continue 
        }
        assert k == 'mode'
        assert v == item.value
    }
}
module main

import asn1

const data = [u8(0x30), 0x82, 0x05, 0x4c, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01,
	0x0b, 0xa3, 0x0c, 0x1b, 0x0a, 0x47, 0x41, 0x4c, 0x41, 0x58, 0x59, 0x2e, 0x4c, 0x41, 0x4e, 0xa4,
	0x17, 0x30, 0x15, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0e, 0x30, 0x0c, 0x1b, 0x0a, 0x62, 0x6f,
	0x62, 0x62, 0x61, 0x2d, 0x66, 0x65, 0x74, 0x74, 0xa5, 0x82, 0x04, 0x07, 0x61, 0x82, 0x04, 0x03,
	0x30, 0x82, 0x03, 0xff, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x0c, 0x1b, 0x0a, 0x47, 0x41, 0x4c,
	0x41, 0x58, 0x59, 0x2e, 0x4c, 0x41, 0x4e, 0xa2, 0x1f, 0x30, 0x1d, 0xa0, 0x03, 0x02, 0x01, 0x01,
	0xa1, 0x16, 0x30, 0x14, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0a, 0x47, 0x41,
	0x4c, 0x41, 0x58, 0x59, 0x2e, 0x4c, 0x41, 0x4e, 0xa3, 0x82, 0x03, 0xc7, 0x30, 0x82, 0x03, 0xc3,
	0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x82, 0x03, 0xb5, 0x04, 0x82,
	0x03, 0xb1, 0x3b, 0xd1, 0x93, 0xd9, 0x09, 0x5c, 0x40, 0x7e, 0xd3, 0x35, 0xcc, 0x9c, 0x13, 0xfe,
	0xf7, 0xa6, 0x51, 0xef, 0x45, 0x63, 0x24, 0x26, 0x91, 0x87, 0x8c, 0x75, 0x9b, 0x88, 0x3d, 0xd2,
	0x32, 0xe0, 0xec, 0xaa, 0x41, 0xe0, 0xd3, 0xf0, 0x53, 0x3b, 0xe8, 0xfc, 0x03, 0x40, 0xe9, 0x17,
	0x20, 0x66, 0x14, 0x9a, 0xae, 0x25, 0x7d, 0x68, 0x0c, 0xb6, 0xca, 0xc9, 0xa6, 0x14, 0x5d, 0x86,
	0xce, 0x0d, 0x1a, 0x41, 0x8c, 0xa1, 0x86, 0x4b, 0xa0, 0x89, 0xcb, 0x35, 0xcf, 0xc2, 0xac, 0xba,
	0x77, 0xfb, 0x69, 0x5a, 0x3d, 0x2b, 0xd0, 0x8f, 0x81, 0x3f, 0x7f, 0x84, 0xa6, 0x19, 0x2b, 0x40,
	0x75, 0x24, 0xc9, 0x53, 0xb2, 0x33, 0x22, 0x5a, 0xba, 0xa5, 0xbf, 0x8e, 0xa8, 0xff, 0x0b, 0x5a,
	0xed, 0x00, 0x06, 0x1b, 0xa0, 0x47, 0x88, 0x1e, 0xb6, 0x49, 0xab, 0x11, 0xbe, 0xc1, 0xd8, 0x50,
	0x53, 0x19, 0x4e, 0xd6, 0xda, 0x72, 0x3a, 0xc0, 0x69, 0xd3, 0x8e, 0xfd, 0x0f, 0xfe, 0xce, 0xd5,
	0xb2, 0x42, 0x37, 0xcc, 0x81, 0x14, 0xe8, 0x75, 0x77, 0x47, 0x26, 0x7f, 0x2e, 0xe8, 0x1c, 0x5c,
	0x42, 0x50, 0x79, 0x88, 0x6e, 0xe8, 0x1a, 0xee, 0x55, 0xaf, 0xd2, 0xc0, 0x3b, 0xdf, 0x93, 0xae,
	0x4e, 0x0b, 0x59, 0xdf, 0x75, 0xd4, 0x34, 0x18, 0x16, 0x9c, 0x21, 0x80, 0xbc, 0x98, 0x8c, 0xac,
	0xdc, 0x96, 0xae, 0x2c, 0x38, 0xf1, 0xaf, 0x49, 0x6f, 0xf1, 0x4d, 0xa6, 0xe2, 0xa3, 0x06, 0xe9,
	0x62, 0x4c, 0xfe, 0x29, 0x42, 0x13, 0x4a, 0x08, 0x16, 0xa4, 0xe1, 0x6f, 0x0a, 0xab, 0xe6, 0xd0,
	0x19, 0xd1, 0xce, 0x23, 0x10, 0x0d, 0x7b, 0x70, 0x77, 0x6d, 0xb8, 0x81, 0x46, 0x70, 0xaa, 0xb8,
	0xb6, 0x19, 0x8a, 0x09, 0x63, 0xb2, 0x60, 0xb0, 0x93, 0xab, 0xf7, 0xd8, 0x97, 0x5b, 0xd0, 0x9a,
	0x9d, 0xf4, 0x0c, 0xff, 0x9a, 0xda, 0xbd, 0x83, 0x89, 0x7a, 0x09, 0xff, 0xf3, 0xc6, 0x3d, 0xc4,
	0xd7, 0x11, 0xb9, 0x12, 0x56, 0x02, 0x55, 0x9e, 0xc6, 0x97, 0xee, 0x39, 0x36, 0xf2, 0xee, 0x3e,
	0xec, 0x26, 0x0a, 0x97, 0xeb, 0xae, 0x58, 0x34, 0xb6, 0x2d, 0x4d, 0x80, 0x96, 0x0b, 0x62, 0x2b,
	0x60, 0xf1, 0x5f, 0xb8, 0x24, 0x3e, 0xe6, 0xb6, 0x38, 0x6b, 0xf9, 0x80, 0xc7, 0xd1, 0x61, 0x08,
	0xb1, 0x5f, 0x52, 0xf3, 0x54, 0x0d, 0x97, 0xfe, 0xb1, 0x58, 0xc6, 0x99, 0x0b, 0x6c, 0x6e, 0x61,
	0x91, 0xf2, 0xfe, 0xa6, 0x83, 0x35, 0xf9, 0xd1, 0x1d, 0x6c, 0x67, 0xc6, 0xf0, 0xdd, 0xd9, 0x3a,
	0x9e, 0x83, 0x19, 0x7b, 0x9e, 0x4e, 0x1f, 0x7b, 0x5c, 0xb1, 0xc5, 0xe3, 0x38, 0xd3, 0xff, 0x26,
	0x89, 0x3b, 0x79, 0xfb, 0xa4, 0x12, 0xf6, 0x5d, 0x35, 0x0f, 0xcf, 0x10, 0x09, 0x96, 0x9d, 0x9a,
	0x64, 0xa1, 0x52, 0xe4, 0x05, 0x0c, 0xe8, 0xec, 0xfd, 0xc9, 0xc6, 0x8b, 0xde, 0xd3, 0x19, 0xb4,
	0x7c, 0x02, 0x57, 0x4d, 0x7b, 0x95, 0x97, 0x61, 0x5f, 0x5c, 0x10, 0x12, 0xe6, 0x90, 0xd9, 0x66,
	0xc3, 0x49, 0x04, 0x40, 0x65, 0x49, 0x4f, 0x1b, 0xac, 0x29, 0x30, 0x6c, 0x59, 0xcb, 0xf9, 0x0e,
	0x47, 0xa8, 0xbc, 0xa6, 0xd4, 0x10, 0x6b, 0x8e, 0x99, 0xde, 0x21, 0x07, 0x55, 0x08, 0xd1, 0x4c,
	0xff, 0x0b, 0xfc, 0xc0, 0x92, 0xc6, 0xf4, 0x91, 0x2c, 0xc9, 0x92, 0xde, 0x84, 0x90, 0xa6, 0x9a,
	0xd6, 0x6e, 0xdd, 0xaa, 0x6a, 0x56, 0x7a, 0xe3, 0xd0, 0x78, 0x73, 0x7b, 0x07, 0x6c, 0x42, 0xd1,
	0xaf, 0x9a, 0x8b, 0x1b, 0x6b, 0xbb, 0x1e, 0x1f, 0xa0, 0xb9, 0x32, 0xc2, 0x90, 0x51, 0x95, 0x28,
	0xe3, 0x51, 0x72, 0x02, 0xc5, 0x1b, 0x30, 0x21, 0x2b, 0xfd, 0x04, 0x32, 0x4a, 0xd4, 0x93, 0x60,
	0x1c, 0x59, 0xe2, 0xd7, 0xd1, 0x55, 0xee, 0x5f, 0xd6, 0x85, 0xf3, 0x28, 0x24, 0x31, 0x98, 0x30,
	0xce, 0x4d, 0x0d, 0xfb, 0x3e, 0x1d, 0x97, 0xc1, 0x20, 0x56, 0xc8, 0x7a, 0x43, 0x8b, 0x82, 0xa8,
	0x9f, 0x6a, 0x27, 0x77, 0x4d, 0x8b, 0x9b, 0x0f, 0x68, 0x16, 0x1d, 0x31, 0x51, 0xa8, 0xca, 0xab,
	0x2a, 0xec, 0x8a, 0xb8, 0x9a, 0xf3, 0x6c, 0xb3, 0x4f, 0x76, 0xd3, 0x6b, 0x18, 0x76, 0x73, 0xa0,
	0x49, 0x6e, 0x94, 0x24, 0x6a, 0xe8, 0x44, 0x0a, 0xf5, 0x4d, 0x3b, 0x7a, 0xd8, 0xa7, 0x05, 0xa3,
	0xd8, 0xad, 0xa5, 0xc6, 0x47, 0x83, 0x7f, 0x48, 0xb4, 0x23, 0x34, 0x07, 0xb8, 0xf8, 0x70, 0xd6,
	0xa2, 0xed, 0xa1, 0x8b, 0xff, 0xb5, 0x88, 0xbf, 0x94, 0x0b, 0x2b, 0x60, 0xf6, 0x9a, 0x2f, 0x6e,
	0x26, 0xac, 0x62, 0xcb, 0xff, 0x6f, 0xd6, 0x4c, 0xe2, 0xd6, 0xcf, 0xee, 0xa7, 0x00, 0x9e, 0x75,
	0x4f, 0x15, 0x63, 0x38, 0x15, 0xe3, 0x48, 0x42, 0x8a, 0xf7, 0xf0, 0x6c, 0x5b, 0x47, 0xd8, 0xdd,
	0x5e, 0x8d, 0x8e, 0x62, 0xe5, 0x1d, 0x4d, 0xb8, 0x20, 0x8f, 0x3b, 0xc6, 0xd4, 0xfd, 0x1f, 0x68,
	0xf7, 0xdb, 0xae, 0x90, 0xc2, 0xba, 0xd9, 0x27, 0xee, 0xc5, 0x49, 0x10, 0x69, 0x22, 0xaf, 0xf7,
	0x05, 0x70, 0xf5, 0x3f, 0x89, 0xef, 0x2f, 0x1f, 0x30, 0xbc, 0x97, 0xd4, 0xcc, 0xdd, 0x75, 0x97,
	0x25, 0x44, 0x54, 0x11, 0x98, 0x4f, 0xaf, 0xb2, 0x95, 0x9c, 0xfb, 0x5d, 0xa5, 0xb3, 0x1f, 0x4d,
	0x92, 0xaf, 0x4b, 0xee, 0xba, 0xb9, 0x8d, 0xa5, 0x30, 0xdc, 0xc0, 0xdc, 0x35, 0xee, 0xc8, 0x06,
	0x93, 0x89, 0x86, 0x54, 0x4f, 0xc6, 0xee, 0x57, 0xa7, 0xe0, 0x0a, 0x84, 0x8b, 0xb1, 0x29, 0x35,
	0xef, 0xae, 0x88, 0xcc, 0xec, 0x30, 0xc1, 0x39, 0x0e, 0x79, 0x5a, 0xbf, 0x49, 0xcf, 0x91, 0x19,
	0x1f, 0x35, 0x69, 0x6d, 0xbc, 0x74, 0xfc, 0x5b, 0x13, 0x3b, 0x7b, 0xab, 0x46, 0x22, 0x6a, 0x4b,
	0xd5, 0xd3, 0x97, 0x69, 0xab, 0x1a, 0x05, 0xc8, 0x99, 0x3b, 0x5f, 0xbf, 0x5f, 0xb4, 0x36, 0x8f,
	0x4a, 0x79, 0x71, 0x87, 0xb9, 0x7b, 0xcf, 0x7a, 0xa1, 0xb6, 0x4e, 0xb3, 0x39, 0xc0, 0x9d, 0x8d,
	0x1c, 0x6f, 0x4d, 0x8b, 0x18, 0x2a, 0xee, 0x64, 0x40, 0x03, 0x5a, 0x41, 0x4c, 0x94, 0xe7, 0x2d,
	0xde, 0x7b, 0xdc, 0xce, 0xa7, 0x3a, 0x2f, 0xe9, 0x1c, 0x8d, 0x49, 0xf0, 0xa0, 0xbb, 0x3a, 0xfc,
	0x37, 0x5e, 0x3d, 0x08, 0xd5, 0x5a, 0xd8, 0x7a, 0x26, 0xff, 0x2f, 0xde, 0xbb, 0x3d, 0xa6, 0xcb,
	0x35, 0x7a, 0x90, 0xb6, 0x2b, 0xf4, 0x8a, 0x0f, 0xbc, 0x15, 0x1a, 0x08, 0xe1, 0xb5, 0xb6, 0x0e,
	0x9b, 0x34, 0x5e, 0xc3, 0xd6, 0x86, 0x3d, 0x2f, 0x22, 0x0f, 0xcc, 0xde, 0x7d, 0xed, 0x43, 0x6f,
	0x34, 0x87, 0x6f, 0x50, 0x35, 0x03, 0xba, 0xde, 0x5c, 0xfd, 0x3a, 0xb8, 0x94, 0x05, 0xa1, 0x5c,
	0x46, 0x9d, 0x85, 0xaa, 0x27, 0xd8, 0x9b, 0x3a, 0x4e, 0x45, 0x22, 0x2f, 0x75, 0x8c, 0x03, 0x59,
	0x66, 0x23, 0x06, 0x22, 0x4a, 0xe9, 0x6a, 0xfc, 0x35, 0x52, 0x75, 0xd7, 0xf6, 0xcb, 0x6e, 0xa5,
	0x61, 0xe2, 0x8e, 0xa6, 0x82, 0x01, 0x0c, 0x30, 0x82, 0x01, 0x08, 0xa0, 0x03, 0x02, 0x01, 0x17,
	0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x81, 0xfb, 0x04, 0x81, 0xf8, 0x99, 0xfd, 0x9a, 0x2a, 0x69,
	0xec, 0x57, 0xa6, 0x9f, 0x9d, 0xd0, 0xb1, 0x05, 0xff, 0xf6, 0xae, 0x34, 0x24, 0xa4, 0x91, 0x7d,
	0x8c, 0x40, 0xe1, 0x18, 0x01, 0xb3, 0x29, 0x64, 0x5c, 0x1b, 0x8c, 0x4f, 0xea, 0xc6, 0x95, 0x01,
	0x26, 0x9b, 0xc6, 0xb4, 0xe2, 0xa4, 0x40, 0x7a, 0xc8, 0x7a, 0xd5, 0x09, 0x55, 0xf8, 0xb7, 0xb4,
	0x99, 0xd7, 0x62, 0x88, 0x69, 0x05, 0x1a, 0xdc, 0x84, 0xd2, 0x7b, 0x17, 0xe2, 0x3c, 0xe4, 0x25,
	0x9c, 0x90, 0x40, 0x83, 0x91, 0x33, 0x0a, 0x74, 0x2c, 0xe1, 0x70, 0x81, 0xda, 0x85, 0x3c, 0x76,
	0x93, 0x67, 0xda, 0xdf, 0x12, 0xfc, 0x08, 0x38, 0x0b, 0xa2, 0x78, 0xf0, 0xdf, 0x08, 0xeb, 0xac,
	0xe3, 0xfa, 0xfe, 0x5c, 0xe6, 0x5c, 0x79, 0x21, 0xdf, 0xe4, 0x89, 0xf0, 0x21, 0x3b, 0xb5, 0x99,
	0xce, 0x79, 0x1e, 0x6b, 0xcf, 0x4d, 0xac, 0x1f, 0xa8, 0xc7, 0x23, 0x29, 0x1d, 0xea, 0x52, 0x0b,
	0xa9, 0xa6, 0xd8, 0xeb, 0xac, 0x74, 0x2a, 0x50, 0x1b, 0xc5, 0x19, 0xde, 0x1a, 0x9e, 0x9a, 0x12,
	0xba, 0x6f, 0xdf, 0x28, 0x7b, 0xdc, 0x08, 0x4f, 0x55, 0xcf, 0x69, 0xae, 0x37, 0x2d, 0x7c, 0x9c,
	0x28, 0xb4, 0x0f, 0x37, 0x0f, 0x29, 0xe3, 0x93, 0xf0, 0xe5, 0xc1, 0xc1, 0xdb, 0x8b, 0xb1, 0x00,
	0xa9, 0x86, 0x77, 0x77, 0x63, 0xa6, 0x20, 0xe1, 0x2e, 0x8d, 0xdb, 0x89, 0xb6, 0x94, 0xf8, 0xeb,
	0x5d, 0x32, 0x57, 0x2b, 0x01, 0x4d, 0xae, 0xaf, 0xf1, 0x97, 0xe0, 0x36, 0x39, 0xc9, 0x8c, 0x8b,
	0xca, 0x54, 0x92, 0x53, 0x09, 0xf5, 0x23, 0x05, 0xf8, 0xb2, 0x68, 0x77, 0xe0, 0xac, 0xba, 0x6e,
	0xcd, 0x93, 0xce, 0xa4, 0x01, 0x43, 0x55, 0x6f, 0x2b, 0xf1, 0xb2, 0x1c, 0x89, 0x05, 0x28, 0x3e,
	0xad, 0x63, 0x20]

fn main() {
	seq, _ := asn1.Sequence.decode(data, 0)!
	els := seq.elements()!
	tt_0 := els[0].as_raw_element()
	tt0 := tt_0.as_tagged()!
	dump(tt0.inner_tag())
	inner := tt0.as_inner()
	int0 := inner as asn1.Integer
	dump(int0.tag())
}

/* Output dump(seq)
[examples/kdc.v:103] seq: asn1.Sequence{
    tag: asn1.Tag{
        class: universal
        constructed: true
        number: 16
    }
    elements: [asn1.Encoder(asn1.Tagged{
        expected: asn1.Tag{
            class: context
            constructed: true
            number: 0
        }
        mode: explicit
        inner: asn1.Encoder(INTEGER 5)
    }), asn1.Encoder(asn1.Tagged{
        expected: asn1.Tag{
            class: context
            constructed: true
            number: 1
        }
        mode: explicit
        inner: asn1.Encoder(INTEGER 11)
    }), asn1.Encoder(asn1.Tagged{
        expected: asn1.Tag{
            class: context
            constructed: true
            number: 3
        }
        mode: explicit
        inner: asn1.Encoder(asn1.ASN1Object{
            tag: asn1.Tag{
                class: universal
                constructed: false
                number: 27
            }
            values: [71, 65, 76, 65, 88, 89, 46, 76, 65, 78]
        })
    }), asn1.Encoder(asn1.Tagged{
        expected: asn1.Tag{
            class: context
            constructed: true
            number: 4
        }
        mode: explicit
        inner: asn1.Encoder(asn1.Sequence{
            tag: asn1.Tag{
                class: universal
                constructed: true
                number: 16
            }
            elements: [asn1.Encoder(asn1.Tagged{
                expected: asn1.Tag{
                    class: context
                    constructed: true
                    number: 0
                }
                mode: explicit
                inner: asn1.Encoder(INTEGER 1)
            }), asn1.Encoder(asn1.Tagged{
                expected: asn1.Tag{
                    class: context
                    constructed: true
                    number: 1
                }
                mode: explicit
                inner: asn1.Encoder(asn1.Sequence{
                    tag: asn1.Tag{
                        class: universal
                        constructed: true
                        number: 16
                    }
                    elements: [asn1.Encoder(asn1.ASN1Object{
                        tag: asn1.Tag{
                            class: universal
                            constructed: false
                            number: 27
                        }
                        values: [98, 111, 98, 98, 97, 45, 102, 101, 116, 116]
                    })]
                })
            })]
        })
    }), asn1.Encoder(asn1.Tagged{
        expected: asn1.Tag{
            class: context
            constructed: true
            number: 5
        }
        mode: explicit
        inner: asn1.Encoder(asn1.ASN1Object{
            tag: asn1.Tag{
                class: application
                constructed: true
                number: 1
            }
            values: [48, 130, 3, 255, 160, 3, 2, 1, 5, 161, 12, 27, 10, 71, 65, 76, 65, 88, 89, 46, 76, 65, 78, 162, 31, 48, 29, 160, 3, 2, 1, 1, 161, 22, 48, 20, 27, 6, 107, 114, 98, 116, 103, 116, 27, 10, 71, 65, 76, 65, 88, 89, 46, 76, 65, 78, 163, 130, 3, 199, 48, 130, 3, 195, 160, 3, 2, 1, 18, 161, 3, 2, 1, 2, 162, 130, 3, 181, 4, 130, 3, 177, 59, 209, 147, 217, 9, 92, 64, 126, 211, 53, 204, 156, 19, 254, 247, 166, 81, 239, 69, 99, 36, 38, 145, 135, 140, 117, 155, 136, 61, 210, 50, 224, 236, 170, 65, 224, 211, 240, 83, 59, 232, 252, 3, 64, 233, 23, 32, 102, 20, 154, 174, 37, 125, 104, 12, 182, 202, 201, 166, 20, 93, 134, 206, 13, 26, 65, 140, 161, 134, 75, 160, 137, 203, 53, 207, 194, 172, 186, 119, 251, 105, 90, 61, 43, 208, 143, 129, 63, 127, 132, 166, 25, 43, 64, 117, 36, 201, 83, 178, 51, 34, 90, 186, 165, 191, 142, 168, 255, 11, 90, 237, 0, 6, 27, 160, 71, 136, 30, 182, 73, 171, 17, 190, 193, 216, 80, 83, 25, 78, 214, 218, 114, 58, 192, 105, 211, 142, 253, 15, 254, 206, 213, 178, 66, 55, 204, 129, 20, 232, 117, 119, 71, 38, 127, 46, 232, 28, 92, 66, 80, 121, 136, 110, 232, 26, 238, 85, 175, 210, 192, 59, 223, 147, 174, 78, 11, 89, 223, 117, 212, 52, 24, 22, 156, 33, 128, 188, 152, 140, 172, 220, 150, 174, 44, 56, 241, 175, 73, 111, 241, 77, 166, 226, 163, 6, 233, 98, 76, 254, 41, 66, 19, 74, 8, 22, 164, 225, 111, 10, 171, 230, 208, 25, 209, 206, 35, 16, 13, 123, 112, 119, 109, 184, 129, 70, 112, 170, 184, 182, 25, 138, 9, 99, 178, 96, 176, 147, 171, 247, 216, 151, 91, 208, 154, 157, 244, 12, 255, 154, 218, 189, 131, 137, 122, 9, 255, 243, 198, 61, 196, 215, 17, 185, 18, 86, 2, 85, 158, 198, 151, 238, 57, 54, 242, 238, 62, 236, 38, 10, 151, 235, 174, 88, 52, 182, 45, 77, 128, 150, 11, 98, 43, 96, 241, 95, 184, 36, 62, 230, 182, 56, 107, 249, 128, 199, 209, 97, 8, 177, 95, 82, 243, 84, 13, 151, 254, 177, 88, 198, 153, 11, 108, 110, 97, 145, 242, 254, 166, 131, 53, 249, 209, 29, 108, 103, 198, 240, 221, 217, 58, 158, 131, 25, 123, 158, 78, 31, 123, 92, 177, 197, 227, 56, 211, 255, 38, 137, 59, 121, 251, 164, 18, 246, 93, 53, 15, 207, 16, 9, 150, 157, 154, 100, 161, 82, 228, 5, 12, 232, 236, 253, 201, 198, 139, 222, 211, 25, 180, 124, 2, 87, 77, 123, 149, 151, 97, 95, 92, 16, 18, 230, 144, 217, 102, 195, 73, 4, 64, 101, 73, 79, 27, 172, 41, 48, 108, 89, 203, 249, 14, 71, 168, 188, 166, 212, 16, 107, 142, 153, 222, 33, 7, 85, 8, 209, 76, 255, 11, 252, 192, 146, 198, 244, 145, 44, 201, 146, 222, 132, 144, 166, 154, 214, 110, 221, 170, 106, 86, 122, 227, 208, 120, 115, 123, 7, 108, 66, 209, 175, 154, 139, 27, 107, 187, 30, 31, 160, 185, 50, 194, 144, 81, 149, 40, 227, 81, 114, 2, 197, 27, 48, 33, 43, 253, 4, 50, 74, 212, 147, 96, 28, 89, 226, 215, 209, 85, 238, 95, 214, 133, 243, 40, 36, 49, 152, 48, 206, 77, 13, 251, 62, 29, 151, 193, 32, 86, 200, 122, 67, 139, 130, 168, 159, 106, 39, 119, 77, 139, 155, 15, 104, 22, 29, 49, 81, 168, 202, 171, 42, 236, 138, 184, 154, 243, 108, 179, 79, 118, 211, 107, 24, 118, 115, 160, 73, 110, 148, 36, 106, 232, 68, 10, 245, 77, 59, 122, 216, 167, 5, 163, 216, 173, 165, 198, 71, 131, 127, 72, 180, 35, 52, 7, 184, 248, 112, 214, 162, 237, 161, 139, 255, 181, 136, 191, 148, 11, 43, 96, 246, 154, 47, 110, 38, 172, 98, 203, 255, 111, 214, 76, 226, 214, 207, 238, 167, 0, 158, 117, 79, 21, 99, 56, 21, 227, 72, 66, 138, 247, 240, 108, 91, 71, 216, 221, 94, 141, 142, 98, 229, 29, 77, 184, 32, 143, 59, 198, 212, 253, 31, 104, 247, 219, 174, 144, 194, 186, 217, 39, 238, 197, 73, 16, 105, 34, 175, 247, 5, 112, 245, 63, 137, 239, 47, 31, 48, 188, 151, 212, 204, 221, 117, 151, 37, 68, 84, 17, 152, 79, 175, 178, 149, 156, 251, 93, 165, 179, 31, 77, 146, 175, 75, 238, 186, 185, 141, 165, 48, 220, 192, 220, 53, 238, 200, 6, 147, 137, 134, 84, 79, 198, 238, 87, 167, 224, 10, 132, 139, 177, 41, 53, 239, 174, 136, 204, 236, 48, 193, 57, 14, 121, 90, 191, 73, 207, 145, 25, 31, 53, 105, 109, 188, 116, 252, 91, 19, 59, 123, 171, 70, 34, 106, 75, 213, 211, 151, 105, 171, 26, 5, 200, 153, 59, 95, 191, 95, 180, 54, 143, 74, 121, 113, 135, 185, 123, 207, 122, 161, 182, 78, 179, 57, 192, 157, 141, 28, 111, 77, 139, 24, 42, 238, 100, 64, 3, 90, 65, 76, 148, 231, 45, 222, 123, 220, 206, 167, 58, 47, 233, 28, 141, 73, 240, 160, 187, 58, 252, 55, 94, 61, 8, 213, 90, 216, 122, 38, 255, 47, 222, 187, 61, 166, 203, 53, 122, 144, 182, 43, 244, 138, 15, 188, 21, 26, 8, 225, 181, 182, 14, 155, 52, 94, 195, 214, 134, 61, 47, 34, 15, 204, 222, 125, 237, 67, 111, 52, 135, 111, 80, 53, 3, 186, 222, 92, 253, 58, 184, 148, 5, 161, 92, 70, 157, 133, 170, 39, 216, 155, 58, 78, 69, 34, 47, 117, 140, 3, 89, 102, 35, 6, 34, 74, 233, 106, 252, 53, 82, 117, 215, 246, 203, 110, 165, 97, 226, 142]
        })
    }), asn1.Encoder(asn1.Tagged{
        expected: asn1.Tag{
            class: context
            constructed: true
            number: 6
        }
        mode: explicit
        inner: asn1.Encoder(asn1.Sequence{
            tag: asn1.Tag{
                class: universal
                constructed: true
                number: 16
            }
            elements: [asn1.Encoder(asn1.Tagged{
                expected: asn1.Tag{
                    class: context
                    constructed: true
                    number: 0
                }
                mode: explicit
                inner: asn1.Encoder(INTEGER 23)
            }), asn1.Encoder(asn1.Tagged{
                expected: asn1.Tag{
                    class: context
                    constructed: true
                    number: 1
                }
                mode: explicit
                inner: asn1.Encoder(INTEGER 2)
            }), asn1.Encoder(asn1.Tagged{
                expected: asn1.Tag{
                    class: context
                    constructed: true
                    number: 2
                }
                mode: explicit
                inner: asn1.Encoder(                asn1.OctetString(���*i�W���б���4$��}�@��)d\O�ƕ&�ƴ�@z�z�     U�����b�i܄�{�<�%��@��3
t,�p�څ<v�g��8
             �x�����\�\y!���!;���yk�M���#)�R
                                            ����t*P����o�({OU�i�7-|�(�7)�����ۋ���wwc� �.�ۉ����]2W+M����69Ɍ��T�S �#��hw଺n͓ΤCUo+��(>�c ))
            })]
        })
    })]
}
*/

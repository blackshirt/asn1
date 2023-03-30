module asn1

import crypto.pem
import encoding.hex

fn test_multienc_add_and_encode() {
	mut en := []Encoder{}
	b := new_boolean(true)

	en.add(b)

	mut seq := new_sequence_from_multiencoder(en)!
	seq.add(new_null())
	out := seq.encode()!

	n := seq.length()
	assert out == [u8(0x30), u8(n), 1, 1, 255, 5, 0]

	seq.add(new_boolean(false))

	seq2 := new_sequence_from_multiencoder([seq])!

	back := seq2.encode()!
	// dump(back)
	outback := der_decode(back)!

	seqb := outback.as_sequence()!
	assert seqb == seq2
}

fn test_simple_certificate_contains_discarded_bytes() {
	data := [u8(0x30), 0x13, 0x02, 0x01, 0x05, 0x16, 0x0e, 0x41, 0x6e, 0x79, 0x62, 0x6f, 0x64,
		0x79, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x3f, 0xff, 0xff]

	out := der_decode(data) or {
		assert err == error('malformed bytes, contains discarded bytes')
		return
	}
}

fn test_parse_ed25519_certificate() ! {
	// blindly parse data
	// data from https://lapo.it/asn1js , with data X.509 certificate based Curve25519 (as per RFC 8410) loaded
	data := [u8(0x30), 0x82, 0x01, 0x7F, 0x30, 0x82, 0x01, 0x31, 0xA0, 0x03, 0x02, 0x01, 0x02,
		0x02, 0x14, 0x7C, 0x8E, 0x64, 0x49, 0xD7, 0x0E, 0xD9, 0x2D, 0x3E, 0x2E, 0x4A, 0x5D, 0x2F,
		0x76, 0xF6, 0x55, 0x42, 0x46, 0xD7, 0x46, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x30,
		0x35, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x54, 0x31,
		0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x06, 0x4D, 0x69, 0x6C, 0x61, 0x6E,
		0x6F, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0C, 0x54, 0x65, 0x73,
		0x74, 0x20, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30,
		0x30, 0x39, 0x30, 0x32, 0x31, 0x33, 0x32, 0x35, 0x32, 0x36, 0x5A, 0x17, 0x0D, 0x33, 0x30,
		0x30, 0x39, 0x30, 0x32, 0x31, 0x33, 0x32, 0x35, 0x32, 0x36, 0x5A, 0x30, 0x35, 0x31, 0x0B,
		0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x54, 0x31, 0x0F, 0x30, 0x0D,
		0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x06, 0x4D, 0x69, 0x6C, 0x61, 0x6E, 0x6F, 0x31, 0x15,
		0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0C, 0x54, 0x65, 0x73, 0x74, 0x20, 0x65,
		0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
		0x03, 0x21, 0x00, 0x3B, 0xA9, 0x2F, 0xFD, 0xCB, 0x17, 0x66, 0xDE, 0x40, 0xA2, 0x92, 0xF7,
		0x93, 0xDE, 0x30, 0xF8, 0x0A, 0x23, 0xA8, 0x31, 0x21, 0x5D, 0xD0, 0x07, 0xD8, 0x63, 0x24,
		0x2E, 0xFF, 0x68, 0x21, 0x85, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D,
		0x0E, 0x04, 0x16, 0x04, 0x14, 0x6B, 0xA5, 0xBD, 0xCF, 0x9D, 0xFA, 0x23, 0x59, 0x78, 0x12,
		0x64, 0x17, 0xAE, 0x1E, 0x72, 0xD8, 0x9A, 0x80, 0x4A, 0xE8, 0x30, 0x1F, 0x06, 0x03, 0x55,
		0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6B, 0xA5, 0xBD, 0xCF, 0x9D, 0xFA, 0x23,
		0x59, 0x78, 0x12, 0x64, 0x17, 0xAE, 0x1E, 0x72, 0xD8, 0x9A, 0x80, 0x4A, 0xE8, 0x30, 0x0F,
		0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF,
		0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41, 0x00, 0x6F, 0x73, 0x77, 0xBE, 0x28,
		0x96, 0x5A, 0x33, 0x36, 0xD7, 0xE5, 0x34, 0xFD, 0x90, 0xF3, 0xFD, 0x40, 0x7F, 0x1F, 0x02,
		0xF9, 0x00, 0x57, 0xF2, 0x16, 0x0F, 0x16, 0x6B, 0x04, 0xBF, 0x65, 0x84, 0xB6, 0x98, 0xD2,
		0xD0, 0xD2, 0xBF, 0x4C, 0xD6, 0x6F, 0x0E, 0xB6, 0xE2, 0xE8, 0x9D, 0x04, 0xA3, 0xE0, 0x99,
		0x50, 0xF9, 0xC2, 0x6D, 0xDE, 0x73, 0xAD, 0x1D, 0x35, 0x57, 0x85, 0x65, 0x86, 0x06]

	out := der_decode(data)!

	assert out is Sequence

	dmp := out.encode()!

	assert dmp == data
}

fn test_ed4418_data() ! {
	// from https://asecuritysite.com/digitalcert/sigs4cd
	/*
	DER: 3043300506032b6571033a00419610a534af127f583b04818cdb7f0ff300b025f2e01682bcae33fd691cee039511df0cddc690ee978426e8b38e50ce5af7dcfba50f704c00
	// decoded as:
	[U] SEQUENCE (30)
  		[U] SEQUENCE (30)
    		[U] OBJECT (06): 1.3.101.113 - Ed448
  		[U] BIT STRING (03): 0xb'00419610A534AF127F583B04818CDB7F0FF300B025F2E01682BCAE33FD691CEE039511DF0CDDC690EE978426E8B38E50CE5AF7DCFBA50F704C00'
  	Public key (9610a534af127f583b04818cdb7f0ff300b025f2e01682bcae33fd, 691cee039511df0cddc690ee978426e8b38e50ce5af7dcfba50f704c00)

	-----BEGIN PUBLIC KEY-----
		MEMwBQYDK2VxAzoAQZYQpTSvEn9YOwSBjNt/D/MAsCXy4BaCvK4z/Wkc7gOVEd8M3caQ7peEJuizjlDOWvfc+6UPcEwA
	-----END PUBLIC KEY-----
	*/
	data := '3043300506032b6571033a00419610a534af127f583b04818cdb7f0ff300b025f2e01682bcae33fd691cee039511df0cddc690ee978426e8b38e50ce5af7dcfba50f704c00'

	bytes := hex.decode(data)!

	out := der_decode(bytes)!
	seq := out.as_sequence()!

	assert seq.elements.len == 2
	assert seq.elements[0] is Sequence
	assert seq.elements[1] is BitString

	el0 := seq.elements[0].as_sequence()!
	sel0 := el0.elements[0].as_oid()!
	assert sel0.str() == '1.3.101.113'
}

fn test_x25519_private_key() ? {
	// taken from https://www.rfc-editor.org/rfc/rfc8410#section-10
	// 10.3 Examples of Ed25519 Private Key

	data := '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----'

	// The same item dumped as asn1 yields:
	/*
	0 30   46: SEQUENCE {
 	2 02    1:   INTEGER 0
	5 30    5:   SEQUENCE {
 	7 06    3:     OBJECT IDENTIFIER
          :       Ed 25519 signature algorithm { 1 3 101 112 }
          :     }
	12 04   34:   OCTET STRING
          :     04 20 D4 EE 72 DB F9 13 58 4A D5 B6 D8 F1 F7 69
          :     F8 AD 3A FE 7C 28 CB F1 D4 FB E0 97 A8 8F 44 75
          :     58 42
          :   }
	*/
	block, _ := pem.decode(data)?

	out := der_decode(block.data)!
	assert out is Sequence
	assert out.length() == 46
	seq := out.as_sequence()!

	assert seq.elements[0] is AsnInteger
	assert seq.elements[1] is Sequence
	b := seq.elements[1].as_sequence()!

	assert b.elements[0] is Oid
	assert b.elements[0].length() == 3

	oid := b.elements[0].as_oid()!
	assert oid.str() == '1.3.101.112'

	assert seq.elements[2] is OctetString
	assert seq.elements[2].length() == 34
}

fn test_example_x25519_certificate() {
	// taken from https://www.rfc-editor.org/rfc/rfc8410.html#section-10
	// 10.2.  Example X25519 Certificate
	data := '-----BEGIN CERTIFICATE-----
MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX
N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD
DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj
ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg
BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v
/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg
w1AH9efZBw==
-----END CERTIFICATE-----'

	// The same item dumped as asn1 yields:
	/*
	0 300: SEQUENCE {
     4 223:   SEQUENCE {
     7   3:     [0] {
     9   1:       INTEGER 2
          :       }
    12   8:     INTEGER 56 01 47 4A 2A 8D C3 30
    22   5:     SEQUENCE {
    24   3:       OBJECT IDENTIFIER
          :         Ed 25519 signature algorithm { 1 3 101 112 }
          :       }
    29  25:     SEQUENCE {
    31  23:       SET {
    33  21:         SEQUENCE {
    35   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
    40  14:           UTF8String 'IETF Test Demo'
          :           }
          :         }
          :       }
    56  30:     SEQUENCE {
    58  13:       UTCTime 01/08/2016 12:19:24 GMT
    73  13:       UTCTime 31/12/2040 23:59:59 GMT
          :       }
    88  25:     SEQUENCE {
    90  23:       SET {
    92  21:         SEQUENCE {
    94   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
    99  14:           UTF8String 'IETF Test Demo'
          :           }
          :         }
          :       }
   115  42:     SEQUENCE {
   117   5:       SEQUENCE {
   119   3:         OBJECT IDENTIFIER
          :           ECDH 25519 key agreement { 1 3 101 110 }
          :         }
   124  33:       BIT STRING
          :         85 20 F0 09 89 30 A7 54 74 8B 7D DC B4 3E F7 5A
          :         0D BF 3A 0D 26 38 1A F4 EB A4 A9 8E AA 9B 4E 6A
          :       }
   159  69:     [3] {
   161  67:       SEQUENCE {
   163  15:         SEQUENCE {
   165   3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
 170   1:           BOOLEAN TRUE
   173   5:           OCTET STRING, encapsulates {
   175   3:             SEQUENCE {
   177   1:               BOOLEAN FALSE
          :               }
          :             }
          :           }
   180  14:         SEQUENCE {
   182   3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
   187   1:           BOOLEAN FALSE
   190   4:           OCTET STRING, encapsulates {
   192   2:             BIT STRING 3 unused bits
          :               '10000'B (bit 4)
          :             }
          :           }
   196  32:         SEQUENCE {
   198   3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
   203   1:           BOOLEAN FALSE
   206  22:           OCTET STRING, encapsulates {
   208  20:             OCTET STRING
          :               9B 1F 5E ED ED 04 33 85 E4 F7 BC 62 3C 59 75
          :               B9 0B C8 BB 3B
          :             }
          :           }
          :         }
          :       }
          :     }
   230   5:   SEQUENCE {
   232   3:     OBJECT IDENTIFIER
          :       Ed 25519 signature algorithm { 1 3 101 112 }
          :     }
   237  65:   BIT STRING
          :     AF 23 01 FE DD C9 E6 FF C1 CC A7 3D 74 D6 48 A4
          :     39 80 82 CD DB 69 B1 4E 4D 06 EC F8 1A 25 CE 50
          :     D4 C2 C3 EB 74 6C 4E DD 83 46 85 6E C8 6F 3D CE
          :     1A 18 65 C5 7A C2 7B 50 A0 C3 50 07 F5 E7 D9 07
          :   }
	*/
	block, _ := pem.decode(data)?

	out := der_decode(block.data)!

	assert out is Sequence
	assert out.length() == 300
	if out is Sequence {
		// certificate is arrays of 3 element
		assert out.elements.len == 3
		// last element
		assert out.elements[2] is BitString
		assert out.elements[2].length() == 65
		bts := read_bitstring(out.elements[2].contents()!)!
		exp := [u8(0xAF), 0x23, 0x01, 0xFE, 0xDD, 0xC9, 0xE6, 0xFF, 0xC1, 0xCC, 0xA7, 0x3D, 0x74,
			0xD6, 0x48, 0xA4, 0x39, 0x80, 0x82, 0xCD, 0xDB, 0x69, 0xB1, 0x4E, 0x4D, 0x06, 0xEC,
			0xF8, 0x1A, 0x25, 0xCE, 0x50, 0xD4, 0xC2, 0xC3, 0xEB, 0x74, 0x6C, 0x4E, 0xDD, 0x83,
			0x46, 0x85, 0x6E, 0xC8, 0x6F, 0x3D, 0xCE, 0x1A, 0x18, 0x65, 0xC5, 0x7A, 0xC2, 0x7B,
			0x50, 0xA0, 0xC3, 0x50, 0x07, 0xF5, 0xE7, 0xD9, 0x07]
		assert bts.data == exp
	}
}

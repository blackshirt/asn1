// Ticket          ::= [APPLICATION 1] SEQUENCE {
//    tkt-vno         [0] INTEGER (5),
//    realm           [1] Realm,
//    sname           [2] PrincipalName,
//    enc-part        [3] EncryptedData -- EncTicketPart
// }
struct Ticket {
	tag      asn1.Tag = asn1.new_tag(.application, true, 1) or { panic(err) }
	tkt_vno  int = 5
	realm    Realm
	sname    PrincipalName
	enc_part EncryptedData
}

fn (t Ticket) tag() asn1.Tag {
	return t.tag
}

fn (t Ticket) length(p asn1.Params) int {
	mut n := 0

	mut seq := asn1.Sequence.new(false)!
	el0 := asn1.TaggedType.explicit_context(asn1.Int64.from_i64(t.tkt_kvno)!, 0)!
	el1 := asn1.TaggedType.explicit_context(t.Realm, 1)!
	el2 := asn1.TaggedType.explicit_context(t.sname, 2)!
	el3 := asn1.TaggedType.explicit_context(t.enc_part, 3)!

	// add element to sequence
	seq.add_element(el0)!
	seq.add_element(el1)!
	seq.add_element(el2)!
	seq.add_element(el3)!

	n += seq.packed_length(p)
	return n 
}

fn (t Ticket) encode(mut out []u8, p asn1.Params) ! {
	payload := t.payload(p)!
}

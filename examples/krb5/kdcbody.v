module main

// KDC-REQ-BODY    ::= SEQUENCE {
//        kdc-options             [0] KDCOptions,
//        cname                   [1] PrincipalName OPTIONAL
//                                    -- Used only in AS-REQ --,
//        realm                   [2] Realm
//                                    -- Server's realm
//                                    -- Also client's in AS-REQ --,
//        sname                   [3] PrincipalName OPTIONAL,
//        from                    [4] KerberosTime OPTIONAL,
//        till                    [5] KerberosTime,
//        rtime                   [6] KerberosTime OPTIONAL,
//        nonce                   [7] UInt32,
//        etype                   [8] SEQUENCE OF Int32 -- EncryptionType
//                                    -- in preference order --,
//        addresses               [9] HostAddresses OPTIONAL,
//        enc-authorization-data  [10] EncryptedData OPTIONAL
//                              -- AuthorizationData --,
//        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
//                                      -- NOTE: not empty
//}

struct KdcReqBody {
	kdc_options KDCOptions
	cname       PrincipalName
	realm       Realm
	sname       PrincipalName
	from        KerberosTime
	till        KerberosTime
	rtime       KerberosTime
	nonce       u32
	etype       []u32
	addresses   []HostAddress
	eauth_data  EncryptedData
	add_tickets []Ticket
}

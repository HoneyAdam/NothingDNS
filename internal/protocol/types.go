// Package protocol provides DNS protocol types for NothingDNS.
//
// Record type RData implementations have been moved to dedicated files:
//
//	types_address.go  — A, AAAA, CNAME, DNAME, NS, PTR
//	types_mail.go     — MX, TXT
//	types_auth.go     — SOA, SRV
//	types_security.go — CAA, SSHFP, TLSA
//	types_naming.go   — NAPTR, SVCB params
//	types_svcb.go     — SVCB, HTTPS
//	types_zonemd.go   — ZONEMD

package protocol

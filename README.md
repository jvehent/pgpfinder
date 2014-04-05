PGP Finder
==========

A simple, not so smart, client to search key servers and print the details of
found keys. It's more of a proof of concept for the openpgp Go module than
anything else. And I don't intend to make it particularly useful...

```bash
$ go run pgpfinder.go -search jvehent -v

searching at http://gpg.mozilla.org:80/pks/lookup?op=vindex&options=mr&search=jvehent
querying http://gpg.mozilla.org:80/pks/lookup?op=get&options=mr&search=0x4FB5544F
querying http://gpg.mozilla.org:80/pks/lookup?op=get&options=mr&search=0x3B763E8F
querying http://gpg.mozilla.org:80/pks/lookup?op=get&options=mr&search=0x3556EF3A
found 3 keys on http://gpg.mozilla.org:80 for jvehent

========       Details of Key ID 65BE0EFC4FB5544F       ========
Fingerprint: 6F7071509123FDABD85A43EA65BE0EFC4FB5544F
Creation Time: 2014-01-28 12:23:02 -0500 EST
Pubkey algorithm: RSA
Public Modulus: 2048 bits. Public exponent: 65537
Identities:
- Julien Vehent Mozilla Investigator (Mozilla Investigator Signing Key for Julien Vehent. Contact opsec@mozilla.com) <jvehent+mig@mozilla.com>
	signatures:

================================================================

========       Details of Key ID A3D652173B763E8F       ========
Fingerprint: E60892BB9BD89A69F759A1A0A3D652173B763E8F
Creation Time: 2013-04-30 12:05:37 -0400 EDT
Pubkey algorithm: RSA
Public Modulus: 2048 bits. Public exponent: 65537
Identities:
- Julien Vehent (ulfr) <jvehent@mozilla.com>
	signatures:
	- 5FEE05E6A56E15A3 2013-10-04 12:37:25 -0400 EDT
	- 13CE04062983AB4B 2013-10-11 19:51:43 -0400 EDT
	- FDBE31EE3033CB4E 2014-03-25 17:12:53 -0400 EDT
	- C7578A5395612E47 2014-03-18 13:39:33 -0400 EDT
	- 25ADBFC5B42BC501 2014-03-25 17:09:51 -0400 EDT
	- F0A9E7DCD39E452E 2014-03-18 13:44:55 -0400 EDT
	- B7207AAB28A860CE 2013-10-04 12:24:10 -0400 EDT
	- F2ECB29133DB65A0 2013-05-08 16:10:52 -0400 EDT
	- 87DF65059EF093D3 2014-03-18 13:40:21 -0400 EDT
	- A4AB57D80525636A 2014-03-18 13:41:04 -0400 EDT
	- EC36FEE86B8579BF 2014-03-18 13:41:21 -0400 EDT
	- 39DC218DC20B410B 2014-03-18 13:43:25 -0400 EDT
	- 5CDBCABCB7116A0 2014-03-18 13:49:32 -0400 EDT
	- 7813901286EDAAC4 2014-03-18 13:51:32 -0400 EDT
	- 72E07B272580198E 2014-03-18 14:39:27 -0400 EDT
	- 3342E1B667A38863 2014-03-25 17:11:45 -0400 EDT
	- EAD831C6F616AB35 2013-10-04 13:12:02 -0400 EDT
	- B573F0908DA0D143 2013-05-08 15:47:38 -0400 EDT
	- 9F96B92930380381 2013-10-08 06:53:54 -0400 EDT
	- 80D30F5A3D16045C 2014-03-25 17:29:34 -0400 EDT
	- BC17301B491B3F21 2013-05-07 13:48:47 -0400 EDT
	- D9B347EA9DF43DBB 2013-10-08 09:05:45 -0400 EDT
	- 825E72461A1B8499 2013-10-10 17:42:44 -0400 EDT
	- 8262833620A64C3F 2013-10-04 12:31:31 -0400 EDT
	- 100C9B89DF55A146 2014-03-25 17:09:47 -0400 EDT
	- BD897970048474F9 2014-03-25 17:14:18 -0400 EDT
	- 23BAD351C916B67D 2013-10-04 13:22:52 -0400 EDT
- Julien Vehent (personal) <julien@linuxwall.info>
	signatures:
	- FDBE31EE3033CB4E 2014-03-25 17:12:38 -0400 EDT
	- 25ADBFC5B42BC501 2014-03-25 17:09:37 -0400 EDT
	- F0A9E7DCD39E452E 2014-03-18 13:44:55 -0400 EDT
	- B7207AAB28A860CE 2013-10-04 12:24:10 -0400 EDT
	- EC36FEE86B8579BF 2014-03-18 13:41:21 -0400 EDT
	- 39DC218DC20B410B 2014-03-18 13:43:25 -0400 EDT
	- 5CDBCABCB7116A0 2014-03-18 13:49:32 -0400 EDT
	- 72E07B272580198E 2014-03-18 14:39:24 -0400 EDT
	- F2ECB29133DB65A0 2014-03-25 17:12:16 -0400 EDT
	- 3342E1B667A38863 2014-03-25 17:11:39 -0400 EDT
	- EAD831C6F616AB35 2013-10-04 13:12:02 -0400 EDT
	- 80D30F5A3D16045C 2014-03-25 17:29:34 -0400 EDT
	- 100C9B89DF55A146 2014-03-25 17:09:46 -0400 EDT
	- BD897970048474F9 2014-03-25 17:14:14 -0400 EDT

================================================================

========       Details of Key ID C0826E8B3556EF3A       ========
Fingerprint: 340A3801993728D8C15CA46AC0826E8B3556EF3A
Creation Time: 2005-03-04 06:39:55 -0500 EST
Pubkey algorithm: RSA
Public Modulus: 1024 bits. Public exponent: 41
Identities:
- VEHENT Julien <jvehent@free.fr>
	signatures:
	- C0826E8B3556EF3A 2005-03-04 06:43:21 -0500 EST

================================================================
```

TktBridgeAP
===========

TktBridgeAP is a Windows Authentication Package (AP) that allows arbitrary Security Support Providers (SSPs) to be used to acquire Kerberos tickets.

It uses undocumented Windows APIs and is in no way supported by either PADL Software Pty Ltd or Microsoft. Caveat emptor.

Architecture
------------

You will require a custom GSS-API mechanism / SSP that is supported both by Heimdal and Windows, for example the PADL Moonshot EAP SSP. TktBridgeAP implements [draft-perez-krb-wg-gss-preauth](https://datatracker.ietf.org/doc/html/draft-perez-krb-wg-gss-preauth) but with some simplifications to the protocol. See [here](https://github.com/heimdal/heimdal/blob/master/lib/gssapi/preauth/README.md) for more information.

TktBridgeAP uses SSPI to perform a pre-authentication exchange with a Heimdal KDC that shares a secret with Active Directory. Once the user is authenticated, Heimdal issues a "partial" TGT, and TktBridgeAP passes it to the native Windows Kerberos package which exchanges it for a full TGT containing user authorization data.

KDC configuration
-----------------

Configure a recent Heimdal master with GSS-API and synthetic principal support. In this example we will use the Kerberos realm KERB.PADL.COM and the RADIUS realm AAA.PADL.COM. Note that the TGS principal is served from a keytab: this is because it needs to share a key with Active Directory, and it is not possible to set a password on a TGS account.

/etc/krb5.conf:

```
[libdefaults]
    default_realm = KERB.PADL.COM

[kdc]
    ports = 88/udp 88/tcp
    allow-anonymous = true
    enable_gss_preauth = true
    synthetic_clients = true
    synthetic_clients_max_life = 1d
    synthetic_clients_max_renew = 7d
    gss_mechanisms_allowed = eap-aes128 eap-aes256
    database = {
	default = {
	    dbname = /var/heimdal/heimdal.db
	    realm = KERB.PADL.COM
	}
	krbtgt = {
	    dbname = keytab:/var/heimdal/rodc.keytab
	    realm = KERB.PADL.COM
	}
    }
```

AD configuration
----------------

The Heimdal KDC needs to share a secret with Active Directory. It will appear to Active Directory as a Read Only Domain Controller (RODC). Create the RODC TGS and machine accounts as an administrator using the following LDIF:

```
dn: CN=krbtgt_TktBridgeAP,CN=Users,DC=kerb,DC=padl,DC=com
control: 1.2.840.113556.1.4.1341
description: Ticket Bridge Authentication Package KDC Account
objectClass: user
showInAdvancedViewOnly: TRUE
msDS-SupportedEncryptionTypes: 24

dn: CN=TktBridgeAPKerberos,OU=Domain Controllers,DC=kerb,DC=padl,DC=com
description: Ticket Bridge Authentication Package RODC Account
objectClass: computer
userAccountControl: 83890176
primaryGroupID: 521
dNSHostName: tktbridge.kerb.padl.com
msDS-SupportedEncryptionTypes: 24
mSDS-KrbTgtLink: CN=krbtgt_TktBridgeAP,CN=Users,DC=kerb,DC=padl,DC=com
mSDS-RevealOnDemandGroup: CN=Users,CN=Builtin,DC=kerb,DC=padl,DC=COM
```

Note this enables all users to use GSS pre-authentication: you can restrict this by changing the value of `mSDS-RevalOnDemandGroup` above.

You then need to read back the RODC branch ID from LDAP: it is the integer suffix to the sAMAccountName for the `krbtgt_TktBridgeAP` entry you created above. It is randomly assigned by Active Directory. On my server, it is 30382, so the sAMAccountName is `krbtgt_30382`.

Use `samba-tool` to retrieve the TGS secret from the domain controller, with the following command:

```bash
mkdir /tmp/tktbridgeap
samba-tool drs clone-dc-database KERB.PADL.COM --include-secrets --targetdir=/tmp/tktbridgeap --server=dc1 -UAdministraotr@KERB.PADL.COM
samba-tool domain export-keytab /var/heimdal/rodc.keytab --configfile=/tmp/tktbridgeap/smb.conf --principal=krbtgt_30382
ktutil -k /var/heimdal/rodc.keytab rename krbtgt_30382 krbtgt/KERB.PADL.COM
rm -rf /tmp/tktbridgeap
```

TktBridgeAP configuration
-------------------------

TktBridgeAP should be added to the Security Packages key in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.

You should set the `CloudKerberosTicketRetrievalEnabled` integer value to 1 in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`.

To configure TktBridgeAP itself, set the `KdcHostName` string value in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\TktBridgeAP` to the hostname of the Heimdal KDC you configured above. If none is specified, then the `_kerberos-tkt-bridge` DNS SRV record will be queried for the primary DNS domain.

By default TktBridgeAP will use SPNEGO/NegoEx to authenticate to the KDC. You can force a single package with the `RestrictPackage` key.

To avoid locking out domain users, TktBridgeAP by default will not attempt GSS pre-authentication for any Active Directory domains (including trusted domains). If you wish to positively associate a set of realms, it cna be done with the `DomainSuffixes` registry key. This key is authoritative and will override any checks for matching Active Directory domains.

User configuration
------------------

To enable a user for GSS pre-authentication, they must first be a member of the group specified in `mSDS-RevealOnDemandGroup` above, and they must have their `userPrincipalName` attribute set to the GSS-API initiator name (for example, with EAP, this will be the NAI name such as `lukeh@AAA.PADL.COM`).

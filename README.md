TktBridgeAP
===========

TktBridgeAP is a Windows Authentication Package (AP) that allows arbitrary Security Support Providers (SSPs) to be used to acquire Kerberos tickets.

It uses undocumented Windows APIs and is in no way supported by either PADL Software Pty Ltd or Microsoft. Caveat emptor.

You will require a custom GSS-API mechanism / SSP that is supported both by Heimdal and Windows, for example the EAP SSP we developed. TktBridgeAP implements [draft-perez-krb-wg-gss-preauth](https://datatracker.ietf.org/doc/html/draft-perez-krb-wg-gss-preauth) but with some simplifications to the protocol. See [here](https://github.com/heimdal/heimdal/blob/master/lib/gssapi/preauth/README.md) for more information.

Architecture
------------

TktBridgeAP uses SSPI to perform a pre-authentication exchange with a Heimdal KDC that shares a secret with Active Directory. Once the user is authenticated, Heimdal issues a ‘partial’ ticket granting ticket (TGT) which passes to the native Windows Kerberos package. In turn, Windows exchanges this with Active Directory for a ticket which can be used to perform user logon.

TktBridgeAP is agnostic to the logon credential type and is designed to work with smartcards and custom credential providers, as well as password credentials. It has, however, only been tested with password credentials.

Operation
---------

When a user logs on to a workstation on which TktBridgeAP is installed, the following happens:

* The AP validates that the logon type is supported, the workstation is joined to a domain, and it has authority to authenticate users in the supplied domain
* The credential information supplied by the credential provider is repacked into a form suitable for submitting to SSPI
* The information is used to acquire a SSPI credential handle
* The AP exchanges as many SSPI tokens as necessary with the bridge KDC in order to authenticate the user and acquire a partial TGT
* The partial TGT is made available to the native Kerberos security package
* The native Kerberos security package exchanges the partial ticket for a full one by performing a TGS-REQ to an Active Directory domain controller
* The user is logged on

KDC configuration
-----------------

Configure a recent Heimdal master with GSS-API and synthetic principal support. The Heimdal KDC does not need to contain any principals except for the default ones, and indeed its TGS (krbtgt) entry should be deleted as it will be provided from a keytab.

In this example we will use the Kerberos realm KERB.PADL.COM and the RADIUS realm AAA.PADL.COM. Note that the TGS principal is served from a keytab: this is because it needs to share a key with Active Directory, and it is not possible to set a password on a TGS account.

Below follows an excerpt of the Kerberos configuration file `/etc/krb5.conf`:

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
    krbtgt = {
	dbname = keytab:/var/heimdal/rodc.keytab
	realm = KERB.PADL.COM
    }
	default = {
	    dbname = /var/heimdal/heimdal.db
	    realm = KERB.PADL.COM
	}
    }
```

If you are using a custom GSS mechanism, be sure to configure `/etc/gss/mech` appropriately so Heimdal can find it. Make sure too that there are no library dependency conflicts between it and the version of Heimdal the KDC is built from.

AD configuration
----------------

The Heimdal KDC needs to share a secret with Active Directory. It does so by appearing to Active Directory as a Read Only Domain Controller (RODC). Create the RODC TGS and machine accounts as an administrator using the following LDIF:

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

You then need to read back the RODC branch ID from LDAP by performing a search for `CN=krbtgt_TktBridgeAP` and requesting the `mSDS-SecondaryKrbTgtNumber` attribute. This is an integer ID that is used to distinguish the KDC from other RODCs and the main `krbtgt` account. The ID is randomly assigned by Active Directory. On my test domain controller, it is 30382, so the sAMAccountName is `krbtgt_30382`.

Use `samba-tool` to retrieve this TGS secret from the domain controller, with the following command:

```bash
# export TKTBRIDGEAP_REALM=KERB.PADL.COM
# export TKTBRIDGEAP_BRANCHID=30382
# export TKTBRIDGEAP_KRBTGT="krbtgt_$TKTBRIDGEAP_BRANCHID"
# export TKTBRIDGEAP_DC=dc1.kerb.padl.com

# mkdir /tmp/TktBridgeAP
# samba-tool drs clone-dc-database $TKTBRIDGEAP_REALM --include-secrets --targetdir=/tmp/TktBridgeAP --server=$TKTBRIDGEAP_DC -UAdministrator@$TKTBRIDGEAP_REALM
# samba-tool domain export-keytab /var/heimdal/rodc.keytab --configfile=/tmp/TktBridgeAP/smb.conf --principal=krbtgt_30382
# ktutil -k /var/heimdal/rodc.keytab rename $TKTBRIDGEAP_KRBTGT krbtgt/$TKTBRIDGEAP_REALM
# rm -rf /tmp/TktBridgeAP
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

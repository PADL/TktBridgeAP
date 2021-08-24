TktBridgeAP
===========

TktBridgeAP is a Windows Authentication Package (AP) that allows arbitrary Security Support Providers (SSPs) to be used to acquire Kerberos tickets.

It uses undocumented Windows APIs and is in no way supported by either PADL Software Pty Ltd or Microsoft. Caveat emptor.




[libdefaults]
	default_relam = KERB.PADL.COM
	dns_canonicalize_hostname = false
	dns_lookup_realm = false

[appdefaults]
	eap_gss = {
		default_realm = AAA.PADL.COM
	}

[realms]
	LUKKTONE.COM = {
		kdc = rand.lukktone.com
	}
	KERB.PADL.COM = {
		kdc = dc1.kerb.padl.com
		kpasswd_server = dc1.kerb.padl.com
#		kdc = localhost
	}

[domain_realm]
	rand.local = LUKKTONE.COM
	.lukktone.com = LUKKTONE.COM
	.kerb.padl.com = KERB.PADL.COM
	tktbridge = KERB.PADL.COM

[kadmin]
	default_keys = aes256-cts-hmac-sha1-96:pw-salt aes128-cts-hmac-sha1-96:pw-salt arcfour-hmac-md5:pw-salt

[kdc]
	ports = 88/udp 88/tcp
	allow-anonymous = true
#	enable-pkinit = true
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

[logging]
	kdc = 0-10/STDERR
	krb5 = 0-10/STDERR
	default = 0-10/STDERR


dn: CN=krbtgt_TktBridgeAP,CN=Users,DC=kerb,DC=padl,DC=com
control: 1.2.840.113556.1.4.1341
description: Ticket Bridge Authentication Package KDC Account
objectClass: user
showInAdvancedViewOnly: TRUE
msDS-SupportedEncryptionTypes: 24

# userAccountControl: WORKSTATION_TRUST_ACCOUNT |
#                     TRUSTED_TO_AUTH_FOR_DELEGATION |
#                     PARTIAL_SECRETS_ACCOUNT | 
#
# primaryGroupID: DOMAIN_RID_READONLY_DCS
dn: CN=TktBridgeAPKerberos,OU=Domain Controllers,DC=kerb,DC=padl,DC=com
description: Ticket Bridge Authentication Package RODC Account
objectClass: computer
userAccountControl: 83890176
primaryGroupID: 521
dNSHostName: tktbridge.kerb.padl.com
msDS-SupportedEncryptionTypes: 24
mSDS-KrbTgtLink: CN=krbtgt_TktBridgeAP,CN=Users,DC=kerb,DC=padl,DC=com

  samba-tool domain exportkeytab rodc.keytab --configfile=etc/smb.conf --principal=krbtgt_30382

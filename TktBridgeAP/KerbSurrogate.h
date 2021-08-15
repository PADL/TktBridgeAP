/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    KerbSurrogate.h

Abstract:

    Interface between SPM surrogate API and Kerberos package.

Environment:

    Local Security Authority (LSA)

--*/

#pragma once

typedef struct _KERB_AS_REP_CREDENTIAL {
	ULONG Version;
	ULONG Flags;
	ULONG TgtMessageOffset;
	ULONG TgtMessageSize;
	ULONG TgtClientKeyOffset;
	ULONG TgtClientKeySize;
	ULONG VsmBindingPrivateKeyOffset;
	ULONG VsmBindingPrivateKeySize;
	ULONG TgtKeyType;
} KERB_AS_REP_CREDENTIAL, *PKERB_AS_REP_CREDENTIAL;

#define KERB_AS_REP_CREDENTIAL_VERSION_1	1

typedef struct _KERB_SURROGATE_LOGON_ENTRY {
	ULONG_PTR Reserved[10];
	NTSTATUS(*RetrieveKerbAsRepCredential)(LUID, PVOID, ULONG, PKERB_AS_REP_CREDENTIAL*);
	PVOID SurrogateData;
} KERB_SURROGATE_LOGON_ENTRY;

/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the
 * disclaimer below) provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED
 * BY THIS LICENSE.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <NTSecPKG.h>

EXTERN_C_START

/*
 * WOW64 (32-bit) client support
 */

typedef struct _KERB_UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} KERB_UNICODE_STRING32;

typedef KERB_UNICODE_STRING32 *PKERB_UNICODE_STRING32;
typedef const KERB_UNICODE_STRING32 *PCKERB_UNICODE_STRING32;

typedef struct _KERB_INTERACTIVE_LOGON_WOW {
    KERB_LOGON_SUBMIT_TYPE MessageType;
    KERB_UNICODE_STRING32 LogonDomainName;
    KERB_UNICODE_STRING32 UserName;
    KERB_UNICODE_STRING32 Password;
} KERB_INTERACTIVE_LOGON_WOW, *PKERB_INTERACTIVE_LOGON_WOW;

typedef struct _KERB_INTERACTIVE_UNLOCK_LOGON_WOW {
    KERB_INTERACTIVE_LOGON_WOW Logon;
    LUID LogonId;
} KERB_INTERACTIVE_UNLOCK_LOGON_WOW, *PKERB_INTERACTIVE_UNLOCK_LOGON_WOW;

typedef struct _KERB_SMART_CARD_LOGON_WOW {
    KERB_LOGON_SUBMIT_TYPE MessageType;
    KERB_UNICODE_STRING32 Pin;
    ULONG CspDataLength;
    ULONG CspData;
} KERB_SMART_CARD_LOGON_WOW, *PKERB_SMART_CARD_LOGON_WOW;

typedef struct _KERB_SMART_CARD_UNLOCK_LOGON_WOW {
    KERB_SMART_CARD_LOGON_WOW Logon;
    LUID LogonId;
} KERB_SMART_CARD_UNLOCK_LOGON_WOW, *PKERB_SMART_CARD_UNLOCK_LOGON_WOW;

typedef struct _KERB_CERTIFICATE_LOGON_WOW {
    KERB_LOGON_SUBMIT_TYPE MessageType;
    KERB_UNICODE_STRING32  DomainName;
    KERB_UNICODE_STRING32  UserName;
    KERB_UNICODE_STRING32  Pin;
    ULONG                  Flags;
    ULONG                  CspDataLength;
    ULONG                  CspData;
} KERB_CERTIFICATE_LOGON_WOW, *PKERB_CERTIFICATE_LOGON_WOW;

typedef struct _KERB_CERTIFICATE_UNLOCK_LOGON_WOW {
    KERB_CERTIFICATE_LOGON_WOW Logon;
    LUID LogonId;
} KERB_CERTIFICATE_UNLOCK_LOGON_WOW, *PKERB_CERTIFICATE_UNLOCK_LOGON_WOW;

/*
 * Smartcard logon
 * https://docs.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info
 */

#pragma pack(push, 2)
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;
    union {
        PVOID   ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer;
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)

/*
 * Callback interface between surrogate and Kerberos packages
 */

/*
 * Windows 10
 */
typedef struct _KERB_AS_REP_TGT_CREDENTIAL {
    ULONG Version;
    ULONG Flags;
    ULONG TgtMessageOffset;
    ULONG TgtMessageLength;
    ULONG TgtClientKeyOffset;
    ULONG TgtClientKeyLength;
    ULONG ReservedOffset;
    ULONG ReservedLength;
    ULONG TgtKeyType;
} KERB_AS_REP_TGT_CREDENTIAL;

/*
 * Windows 11 Insider Preview
 */
typedef struct _KERB_AS_REP_CLOUD_TGT_CREDENTIAL {
    ULONG Version;
    ULONG Flags;
    ULONG ReservedOffset;
    ULONG ReservedLength;
    ULONG TgtMessageOffset;
    ULONG TgtMessageLength;
    ULONG TgtClientKeyOffset;
    ULONG TgtClientKeyLength;
    ULONG TgtKeyType;
    ULONG CloudTgtMessageOffset;
    ULONG CloudTgtMessageLength;
    ULONG CloudTgtClientKeyOffset;
    ULONG CloudTgtClientKeyLength;
    ULONG CloudTgtKeyType;
    ULONG KerberosTopLevelNamesOffset;
    ULONG KerberosTopLevelNamesLength;
    ULONG KdcProxyNameOffset;
    ULONG KdcProxyNameLength;
} KERB_AS_REP_CLOUD_TGT_CREDENTIAL;

typedef union _KERB_AS_REP_CREDENTIAL {
    KERB_AS_REP_TGT_CREDENTIAL TgtCredential;
    KERB_AS_REP_CLOUD_TGT_CREDENTIAL CloudTgtCredential;
} KERB_AS_REP_CREDENTIAL, *PKERB_AS_REP_CREDENTIAL;

#define KERB_AS_REP_CREDENTIAL_TGT_VERSION         1
#define KERB_AS_REP_CREDENTIAL_CLOUD_TGT_VERSION   3

typedef NTSTATUS
(CALLBACK KERB_AS_REP_CALLBACK)(LUID LogonId,
                                PVOID AsRepCallbackData,
                                ULONG Flags,
                                PKERB_AS_REP_CREDENTIAL *ppKerbAsRepCredential);

typedef KERB_AS_REP_CALLBACK *PKERB_AS_REP_CALLBACK;

EXTERN_C __declspec(selectany) const GUID KERB_SURROGATE_LOGON_TYPE =
{ 0x045fbe6b, 0x7995, 0x4205, { 0x91, 0x11, 0x74, 0xfa, 0x9c, 0xdd, 0x3c, 0x27 } };

/*
 * Note: AsRepCallbackData is shared with CloudAP. Care must be
 * taken to ensure that CloudAP never attempts to access data
 * that was allocated by TktBridgeAP.
 */
typedef struct _KERB_SURROGATE_LOGON_DATA {
    ULONG64 Reserved1[8];
    ULONG_PTR Reserved2[2];
    PKERB_AS_REP_CALLBACK AsRepCallback;
    PVOID AsRepCallbackData;
} KERB_SURROGATE_LOGON_DATA, *PKERB_SURROGATE_LOGON_DATA;

EXTERN_C_END

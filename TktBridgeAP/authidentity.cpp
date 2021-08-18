/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    authidentity.cpp

Abstract:

    Convert between auth identity types.

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

#include <ntstatus.h>

static VOID
UnpackUnicodeString(_In_ PVOID BasePtr,
                    _Inout_ PUNICODE_STRING Dest,
                    _In_ PCUNICODE_STRING Source)
{
    Dest->Length = Source->Length;
    Dest->MaximumLength = Source->MaximumLength;
    if (Source->Buffer != nullptr)
        Dest->Buffer = (PWSTR)((PBYTE)BasePtr + (ULONG_PTR)Source->Buffer);
    else
        Dest->Buffer = nullptr;
}

static NTSTATUS
ValidateOffset(_In_ ULONG StructSize,
               _In_ ULONG Offset,
               _In_ ULONG Length)
{
    if (Offset + Length > StructSize)
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);
    else
        RETURN_NTSTATUS(STATUS_SUCCESS);
}



//
// the procedure for how to parse a SEC_WINNT_AUTH_IDENTITY_INFO structure:
//
// 1) First check the first DWORD of SEC_WINNT_AUTH_IDENTITY_INFO, if the first
//   DWORD is 0x200, it is either an AuthIdExw or AuthIdExA, otherwise if the first
//   DWORD is 0x201, the structure is an AuthIdEx2 structure. Otherwise the structure
//   is either an AuthId_a or an AuthId_w.
//
// 2) Secondly check the flags for SEC_WINNT_AUTH_IDENTITY_ANSI or
//   SEC_WINNT_AUTH_IDENTITY_UNICODE, the presence of the former means the structure
//   is an ANSI structure. Otherwise, the structure is the wide version.  Note that
//   AuthIdEx2 does not have an ANSI version so this check does not apply to it.
//
NTSTATUS
CanonicalizeSurrogateLogonAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                       _In_ PVOID ClientBufferBase,
                                       _In_ ULONG SubmitBufferSize,
                                       _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    //
    // Check size is at least 4
    //

    //
    // 0x201 IdentityEx2
    //
    // FUNC_EX2
    // Check non-NULL
    // Check structure size
    // Check 0x201
    // SspiUnmarshallAuthIdentity
    // ValidateAuthIdentity - check offsets
    // SspiCopyAuthIdentity
    // DecryptAuthIdentity: if SspiIsAuthIdentity, then call SspiDecryptAUthIdentity


    *pAuthIdentity = nullptr;
    RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
}

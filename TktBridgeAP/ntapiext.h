/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    ntapiext.h

Abstract:

    Undocumented NTDLL APIs

Environment:

    Local Security Authority (LSA)

--*/

#pragma once

extern "C" {

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE		1
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING	2

NTSTATUS NTAPI
RtlDuplicateUnicodeString(
	_In_ ULONG Flags,
	_In_ PCUNICODE_STRING StringIn,
	_Inout_ PUNICODE_STRING StringOut);

BOOLEAN NTAPI
RtlEqualUnicodeString(
	_In_ PCUNICODE_STRING String1,
	_In_ PCUNICODE_STRING String2,
	_In_ BOOLEAN CaseInSensitive
);

NTSTATUS NTAPI
RtlDuplicateSid(_Out_ PSID *NewSid, _In_ PSID OriginalSid);

VOID NTAPI
RtlFreeSid(_Inout_ PSID Sid);

ULONG NTAPI
RtlLengthSid(_Inout_ PSID Sid);

PVOID NTAPI
RtlAllocateHeap(
	_In_ PVOID HeapHandle,
	_In_ ULONG Flags,
	_In_ SIZE_T Size
);

BOOLEAN NTAPI
RtlFreeHeap(
	_In_ PVOID HeapHandle,
	_In_ ULONG Flags,
	_Frees_ptr_opt_ PVOID BaseAddress
);

NTSTATUS NTAPI
RtlCopySid(
	_In_ ULONG DestinationSidLength,
	_Inout_ PSID DestinationSid,
	_In_ PSID SourceSid
);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToUTF8N(
    __out_bcount_part(UTF8StringMaxByteCount, *UTF8StringActualByteCount) PCHAR  UTF8StringDestination,
    __in                                ULONG  UTF8StringMaxByteCount,
    __out                               PULONG UTF8StringActualByteCount,
    __in_bcount(UnicodeStringByteCount) PCWCH UnicodeStringSource,
    __in                                ULONG  UnicodeStringByteCount
);

NTSYSAPI
NTSTATUS
NTAPI
RtlUTF8ToUnicodeN(
    __out_bcount_part(UnicodeStringMaxByteCount, *UnicodeStringActualByteCount) PWSTR  UnicodeStringDestination,
    __in                             ULONG  UnicodeStringMaxByteCount,
    __out                            PULONG UnicodeStringActualByteCount,
    __in_bcount(UTF8StringByteCount) PCCH   UTF8StringSource,
    __in                             ULONG  UTF8StringByteCount
);

}

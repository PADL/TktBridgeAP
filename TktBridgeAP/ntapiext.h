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
	ULONG Flags,
	PCUNICODE_STRING StringIn,
	PUNICODE_STRING StringOut);

BOOLEAN NTAPI
RtlEqualUnicodeString(
	IN PCUNICODE_STRING String1,
	IN PCUNICODE_STRING String2,
	IN BOOLEAN CaseInSensitive
);

NTSTATUS NTAPI
RtlDuplicateSid(OUT PSID *NewSid, IN PSID OriginalSid);

VOID NTAPI
RtlFreeSid(INOUT PSID Sid);

ULONG NTAPI
RtlLengthSid(IN PSID Sid);

PVOID NTAPI
RtlAllocateHeap(
	IN PVOID HeapHandle,
	IN ULONG Flags,
	IN SIZE_T Size
);

BOOLEAN NTAPI
RtlFreeHeap(
	IN PVOID HeapHandle,
	IN ULONG Flags,
	_Frees_ptr_opt_ PVOID BaseAddress
);

NTSTATUS
NTAPI RtlCopySid(
	IN ULONG DestinationSidLength,
	INOUT PSID DestinationSid,
	IN PSID  SourceSid
);

}

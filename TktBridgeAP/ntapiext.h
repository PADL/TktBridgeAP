/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
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
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

extern "C" {

NTSYSAPI
NTSTATUS NTAPI
RtlGetVersion(_Inout_ PRTL_OSVERSIONINFOW lpVersionInformation);

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE		1
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING	2

NTSYSAPI
NTSTATUS NTAPI
RtlDuplicateUnicodeString(
	_In_ ULONG Flags,
	_In_ PCUNICODE_STRING StringIn,
	_Inout_ PUNICODE_STRING StringOut);

NTSYSAPI
BOOLEAN NTAPI
RtlEqualUnicodeString(
	_In_ PCUNICODE_STRING String1,
	_In_ PCUNICODE_STRING String2,
	_In_ BOOLEAN CaseInSensitive
);

NTSTATUS NTAPI
RtlDuplicateSid(_Out_ PSID *NewSid, _In_ PSID OriginalSid);

NTSYSAPI
VOID NTAPI
RtlFreeSid(_Inout_ PSID Sid);

NTSYSAPI
ULONG NTAPI
RtlLengthSid(_Inout_ PSID Sid);

NTSYSAPI
PVOID NTAPI
RtlAllocateHeap(
	_In_ PVOID HeapHandle,
	_In_ ULONG Flags,
	_In_ SIZE_T Size
);

NTSYSAPI
BOOLEAN NTAPI
RtlFreeHeap(
	_In_ PVOID HeapHandle,
	_In_ ULONG Flags,
	_Frees_ptr_opt_ PVOID BaseAddress
);

NTSYSAPI
NTSTATUS NTAPI
RtlCopySid(
	_In_ ULONG DestinationSidLength,
	_Inout_ PSID DestinationSid,
	_In_ PSID SourceSid
);

NTSYSAPI
NTSTATUS NTAPI
RtlUnicodeToUTF8N(
    __out_bcount_part(UTF8StringMaxByteCount, *UTF8StringActualByteCount) PCHAR  UTF8StringDestination,
    __in                                ULONG  UTF8StringMaxByteCount,
    __out                               PULONG UTF8StringActualByteCount,
    __in_bcount(UnicodeStringByteCount) PCWCH UnicodeStringSource,
    __in                                ULONG  UnicodeStringByteCount
);

NTSYSAPI
NTSTATUS NTAPI
RtlUTF8ToUnicodeN(
    __out_bcount_part(UnicodeStringMaxByteCount, *UnicodeStringActualByteCount) PWSTR  UnicodeStringDestination,
    __in                             ULONG  UnicodeStringMaxByteCount,
    __out                            PULONG UnicodeStringActualByteCount,
    __in_bcount(UTF8StringByteCount) PCCH   UTF8StringSource,
    __in                             ULONG  UTF8StringByteCount
);

NTSYSAPI
NTSTATUS NTAPI
RtlUpcaseUnicodeString(
    _Inout_ PUNICODE_STRING  DestinationString,
    _In_ PCUNICODE_STRING SourceString,
    _In_ BOOLEAN          AllocateDestinationString
);


NTSYSAPI
VOID NTAPI
RtlSecondsSince1970ToTime(
    _In_ ULONG ElapsedSeconds,
    _Out_ PLARGE_INTEGER Time
);

}

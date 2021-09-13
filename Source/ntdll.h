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

EXTERN_C_START

/*
 * UNICODE_STRING
 */
#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE		1
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING	2

NTSYSAPI
NTSTATUS NTAPI
RtlDuplicateUnicodeString(_In_ ULONG Flags,
                          _In_ PCUNICODE_STRING StringIn,
                          _Inout_ PUNICODE_STRING StringOut);

NTSYSAPI
BOOLEAN NTAPI
RtlEqualUnicodeString(_In_ PCUNICODE_STRING String1,
                      _In_ PCUNICODE_STRING String2,
                      _In_ BOOLEAN CaseInSensitive);

NTSYSAPI
NTSTATUS NTAPI
RtlUpcaseUnicodeString(_Inout_ PUNICODE_STRING DestinationString,
                       _In_ PCUNICODE_STRING SourceString,
                       _In_ BOOLEAN AllocateDestinationString);

/*
 * UTF8
 */
NTSYSAPI
NTSTATUS NTAPI
RtlUnicodeToUTF8N(_Out_writes_bytes_(*UTF8StringActualByteCount) PCHAR UTF8StringDestination,
                  _In_ ULONG UTF8StringMaxByteCount,
                  _Out_ PULONG UTF8StringActualByteCount,
                  _In_reads_bytes_(UnicodeStringByteCount) PCWCH UnicodeStringSource,
                  _In_ ULONG UnicodeStringByteCount);
    
NTSYSAPI
NTSTATUS NTAPI
RtlUTF8ToUnicodeN(_Out_writes_bytes_(*UnicodeStringActualByteCount) PWSTR UnicodeStringDestination,
                  _In_ ULONG UnicodeStringMaxByteCount,
                  _Out_ PULONG UnicodeStringActualByteCount,
                  _In_reads_bytes_(UTF8StringByteCount) PCCH UTF8StringSource,
                  _In_ ULONG UTF8StringByteCount);

/*
 * SIDs
 */
NTSYSAPI
ULONG NTAPI
RtlLengthSid(_Inout_ PSID Sid);

NTSYSAPI
NTSTATUS NTAPI
RtlCopySid(_In_ ULONG DestinationSidLength,
           _Inout_ PSID DestinationSid,
           _In_ PSID SourceSid);

/*
 * OS version
 */

NTSYSAPI
NTSTATUS NTAPI
RtlGetVersion(_Inout_ PRTL_OSVERSIONINFOW lpVersionInformation);

EXTERN_C_END

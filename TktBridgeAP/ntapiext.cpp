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

#include "TktBridgeAP.h"

NTSTATUS NTAPI
RtlDuplicateSid(_Out_ PSID *DestinationSid, _In_ PSID SourceSid)
{
    NTSTATUS Status;
    ULONG SidLength;
    PSID Sid;

    *DestinationSid = nullptr;

    if (SourceSid == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    SidLength = RtlLengthSid(SourceSid);

    Sid = RtlAllocateHeap(GetProcessHeap(), 0, SidLength);
    RETURN_NTSTATUS_IF_NULL_ALLOC(Sid);

    Status = RtlCopySid(SidLength, Sid, SourceSid);
    if (!NT_SUCCESS(Status))
        RtlFreeSid(Sid);
    RETURN_NTSTATUS_IF_NULL_ALLOC(Sid);

    *DestinationSid = Sid;

    return STATUS_SUCCESS;
}

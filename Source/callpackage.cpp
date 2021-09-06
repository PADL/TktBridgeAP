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

static NTSTATUS
CallPackageTransferCred(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                        _In_reads_bytes_(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
                        _In_ PVOID ClientBufferBase,
                        _In_ ULONG SubmitBufferLength,
                        _Outptr_result_bytebuffer_(*ReturnBufferLength) PVOID *ProtocolReturnBuffer,
                        _Out_ PULONG ReturnBufferLength,
                        _Out_ PNTSTATUS ProtocolStatus)
{
    auto pTCR = (PSECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST)ProtocolSubmitBuffer;

    if (SubmitBufferLength < sizeof(*pTCR))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    *ProtocolReturnBuffer = LsaSpFunctionTable->AllocateLsaHeap(sizeof(ULONG));
    RETURN_NTSTATUS_IF_NULL_ALLOC(*ProtocolReturnBuffer);

    *static_cast<PULONG>(*ProtocolReturnBuffer) = SecPkgCallPackageTransferCredMessage;
    *ReturnBufferLength = sizeof(ULONG);

    *ProtocolStatus = TransferCredsFromLogonSession(pTCR->OriginLogonId,
                                                    pTCR->DestinationLogonId,
                                                    pTCR->Flags);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

NTSTATUS NTAPI
LsaApCallPackage(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                 _In_reads_bytes_(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
                 _In_ PVOID ClientBufferBase,
                 _In_ ULONG SubmitBufferLength,
                 _Outptr_result_bytebuffer_(*ReturnBufferLength) PVOID *ProtocolReturnBuffer,
                 _Out_ PULONG ReturnBufferLength,
                 _Out_ PNTSTATUS ProtocolStatus)
{
    *ProtocolReturnBuffer = nullptr;
    *ReturnBufferLength = 0;
    *ProtocolStatus = STATUS_INVALID_PARAMETER;

    bool bIsTcbClient = !!(GetCallAttributes() & SECPKG_CALL_IS_TCB);
    if (!bIsTcbClient)
        RETURN_NTSTATUS(STATUS_ACCESS_DENIED);

    auto ulMessageType = *static_cast<PULONG>(ProtocolSubmitBuffer);
    if (SubmitBufferLength < sizeof(ulMessageType))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    NTSTATUS Status;

    switch (ulMessageType) {
    case SecPkgCallPackageTransferCredMessage:
        Status = CallPackageTransferCred(ClientRequest, ProtocolSubmitBuffer,
                                         ClientBufferBase, SubmitBufferLength,
                                         ProtocolReturnBuffer, ReturnBufferLength,
                                         ProtocolStatus);
        break;
    default:
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"LsaApCallPackage: Unknown message type %u", ulMessageType);
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    RETURN_NTSTATUS(Status);
}
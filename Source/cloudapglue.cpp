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

#include "TktBridgeAP.h"

/*
 * This file, along with kerbapglue.cpp, holds some ugly kludges
 * that hopefully can go away in the future.
 *
 * CloudAP assumes that it allocated its callback data and will
 * attempt to free it in LsaApPostLogonUserSurrogate.
 *
 * In order to avoid memory corruption we set the CloudAP ref
 * count (which lives at a different offset to the TktBridgeAP
 * ref count) to ULONG_MAX, and allocate enough padding so that
 * there are (hopefully) no attempts to read beyond the end of
 * the structure.
 *
 * Clearly this is suboptimal. A safer alternative would be to
 * allocate and free our callback data directly from within
 * KerbLogonUserEx3Detour, but this would pile one hack on top
 * of another. Moreover, it would require care to work with
 * cached logons where KerbLogonUserEx3Detour is called twice.
 *
 * We await a documented and stable interface in the LSA, but
 * barring that CloudAP checking AsRepCallback matches its own
 * callback function before dereferencing the callback data would
 * allow this file to go away.
 */

struct _CloudAPCallbackData {
    ULONG_PTR Reserved1[2];
    ULONG_PTR CloudAPRefCount;
    ULONG_PTR Reserved2[18];
    ULONG Reserved3[45];
    ULONG CloudAPFlags;
};

PVOID
AllocateCloudAPCallbackData(VOID)
{
    struct _CloudAPCallbackData *CBData;

    CBData = static_cast<struct _CloudAPCallbackData *>
        (LsaSpFunctionTable->AllocateLsaHeap(sizeof(*CBData)));
    if (CBData == nullptr)
        return nullptr;

    ZeroMemory(CBData, sizeof(*CBData));

    CBData->CloudAPRefCount = ULONG_MAX;
    CBData->CloudAPFlags = 2;

    return CBData;
}

bool
ValidateCloudAPCallbackData(_In_ PVOID pvCBData)
{
    auto CBData = static_cast<struct _CloudAPCallbackData *>(pvCBData);

    if (CBData->CloudAPRefCount != ULONG_MAX) {
        DebugTrace(WINEVENT_LEVEL_WARNING,
                   L"CloudAP reference modified, was %x should be %x: "
                   L"check TktBridgeAP qualified for this build of Windows",
                   static_cast<ULONG>(CBData->CloudAPRefCount), ULONG_MAX);
        return false;
    }

    return true;
}

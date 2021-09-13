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

static const ULONG64 SecondsToStartOf1970 = 0x2b6109100;
static const ULONG64 HundredNanoSecondsInSecond = 10000000LL;

VOID
Seconds64Since1970ToTime(_In_ ULONG64 ElapsedSeconds,
                         _Out_ PLARGE_INTEGER Time)
{
    Time->QuadPart = (ElapsedSeconds + SecondsToStartOf1970) * HundredNanoSecondsInSecond;
}

VOID
TimeToSeconds64Since1970(_In_ PLARGE_INTEGER Time,
                         _Out_ PULONG64 ElapsedSeconds)
{
    *ElapsedSeconds = (Time->QuadPart / HundredNanoSecondsInSecond) - SecondsToStartOf1970;
}

ULONG
GetCallAttributes(VOID)
{
    SECPKG_CALL_INFO CallInfo;

    if (LsaSpFunctionTable == nullptr)
        return 0;

    if (!LsaSpFunctionTable->GetCallInfo(&CallInfo))
        return 0;

    return CallInfo.Attributes;
}

bool
IsLocalHost(_In_ PUNICODE_STRING HostName)
{
    WCHAR MachineName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cchMachineName = sizeof(MachineName) / sizeof(WCHAR);
    UNICODE_STRING MachineNameUS;

    if (!GetComputerName(MachineName, &cchMachineName))
        return FALSE;

    RtlInitUnicodeString(&MachineNameUS, MachineName);

    return RtlEqualUnicodeString(HostName, &MachineNameUS, TRUE);
}

ULONG
RegistryGetULongValueForKey(_In_ const wil::unique_hkey &hKey,
                            _In_z_ PCWSTR KeyName)
{
    ULONG KeyValue = 0;
    DWORD dwResult, dwType = REG_DWORD, dwSize = sizeof(ULONG);

    dwResult = RegQueryValueEx(hKey.get(), KeyName, nullptr, &dwType,
                               reinterpret_cast<PBYTE>(&KeyValue), &dwSize);

    return dwResult == ERROR_SUCCESS && dwType == REG_DWORD ?
        KeyValue : 0;
}

bool
RegistryGetStringValueForKey(_In_ const wil::unique_hkey &hKey,
                             _In_z_ PCWSTR KeyName,
                             _Out_ std::wstring &KeyValue)
{
    auto Result = wil::AdaptFixedSizeToAllocatedResult<std::wstring, 256>(KeyValue,
                                                                          [&](PWSTR Value,
                                                                              size_t ValueLength,
                                                                              size_t *ValueLengthNeededWithNull) -> HRESULT {
        auto Length = static_cast<DWORD>(ValueLength);
        DWORD dwType = REG_SZ;
        auto Status = RegQueryValueEx(hKey.get(), KeyName, 0, &dwType, reinterpret_cast<PBYTE>(Value), &Length);

        *ValueLengthNeededWithNull = (Length / sizeof(WCHAR));

        if (Status == ERROR_SUCCESS && dwType != REG_SZ)
            Status = ERROR_INVALID_PARAMETER;

        return Status == ERROR_MORE_DATA ? S_OK : HRESULT_FROM_WIN32(Status);
                                                                          });

    return Result == S_OK;
}

bool
RegistryGetStringValuesForKey(_In_ const wil::unique_hkey &hKey,
                              _In_z_ PCWSTR KeyName,
                              _Out_ std::vector<std::wstring> &KeyValues)
{
    std::wstring KeyValue;

    auto Result = wil::AdaptFixedSizeToAllocatedResult<std::wstring, 256>(KeyValue,
                                                                          [&](PWSTR Value,
                                                                              size_t ValueLength,
                                                                              size_t *ValueLengthNeededWithNull) -> HRESULT {
        auto Length = static_cast<DWORD>(ValueLength);
        DWORD dwType = REG_MULTI_SZ;
        auto Status = RegQueryValueEx(hKey.get(), KeyName, 0, &dwType, reinterpret_cast<PBYTE>(Value), &Length);

        *ValueLengthNeededWithNull = (Length / sizeof(WCHAR));

        if (Status == ERROR_SUCCESS && dwType != REG_MULTI_SZ)
            Status = ERROR_INVALID_PARAMETER;

        return Status == ERROR_MORE_DATA ? S_OK : HRESULT_FROM_WIN32(Status);
                                                                          });

    KeyValues.clear();

    if (Result != S_OK)
        return false;

    for (auto p = KeyValue.data();
         *p != L'\0';
         p += wcslen(p) + 1) {
        KeyValues.emplace_back(std::wstring(p));
    }

    return true;
}

_Success_(return == STATUS_SUCCESS) NTSTATUS
UnicodeToUTF8Alloc(_In_ PCWSTR wszUnicodeString,
                   _Out_ PCHAR *pszUTF8String)
{
    NTSTATUS Status;
    ULONG cbUTF8String = 0;
    SIZE_T cbUnicodeString = (wcslen(wszUnicodeString) + 1) * sizeof(WCHAR);
    ULONG ulcbUnicodeString;
    PCHAR szUTF8String = nullptr;

    *pszUTF8String = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        WIL_FreeMemory(szUTF8String);
    });

    Status = RtlSizeTToULong(cbUnicodeString, &ulcbUnicodeString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = RtlUnicodeToUTF8N(nullptr, 0, &cbUTF8String, wszUnicodeString, ulcbUnicodeString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    szUTF8String = static_cast<PCHAR>(WIL_AllocateMemory(cbUTF8String));
    RETURN_NTSTATUS_IF_NULL_ALLOC(szUTF8String);

    Status = RtlUnicodeToUTF8N(szUTF8String, cbUTF8String, &cbUTF8String,
                               wszUnicodeString, ulcbUnicodeString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *pszUTF8String = szUTF8String;
    szUTF8String = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

_Success_(return == STATUS_SUCCESS) NTSTATUS
UTF8ToUnicodeAlloc(_In_ const PCHAR szUTF8String,
                   _Out_ PWSTR *pwszUnicodeString)
{
    NTSTATUS Status;
    ULONG cbUnicodeString = 0;
    SIZE_T cbUTF8String = strlen(szUTF8String) + 1;
    ULONG ulcbUTF8String;
    PWSTR wszUnicodeString = nullptr;

    *pwszUnicodeString = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        WIL_FreeMemory(wszUnicodeString);
    });

    Status = RtlSizeTToULong(cbUTF8String, &ulcbUTF8String);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = RtlUTF8ToUnicodeN(nullptr, 0, &cbUnicodeString, szUTF8String, ulcbUTF8String);
    RETURN_IF_NTSTATUS_FAILED(Status);

    wszUnicodeString = static_cast<PWSTR>(WIL_AllocateMemory(cbUnicodeString));
    RETURN_NTSTATUS_IF_NULL_ALLOC(wszUnicodeString);

    Status = RtlUTF8ToUnicodeN(wszUnicodeString, cbUnicodeString, &cbUnicodeString,
                               szUTF8String, ulcbUTF8String);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *pwszUnicodeString = wszUnicodeString;
    wszUnicodeString = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

_Success_(return == STATUS_SUCCESS) NTSTATUS
DuplicateSid(_Out_ PSID *DestinationSid, _In_ PSID SourceSid)
{
    NTSTATUS Status;
    ULONG SidLength;
    PSID Sid = nullptr;

    *DestinationSid = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        WIL_FreeMemory(Sid);
    });

    if (SourceSid == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    SidLength = RtlLengthSid(SourceSid);

    Sid = static_cast<PSID>(WIL_AllocateMemory(SidLength));
    RETURN_NTSTATUS_IF_NULL_ALLOC(Sid);

    Status = RtlCopySid(SidLength, Sid, SourceSid);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *DestinationSid = Sid;
    Sid = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

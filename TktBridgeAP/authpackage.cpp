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

ULONG LsaAuthenticationPackageId = 0;
PLSA_DISPATCH_TABLE LsaDispatchTable = nullptr;
PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable = nullptr;

SECPKG_PARAMETERS SpParameters;
ULONG APFlags = 0;
ULONG APLogLevel = 0;
PWSTR APKdcHostName = nullptr;
PWSTR APRestrictPackage = nullptr;
PWSTR *APDomainSuffixes = nullptr;

extern "C" {
    static LSA_AP_INITIALIZE_PACKAGE InitializePackage;
    static SpInitializeFn SpInitialize;
    static SpShutdownFn SpShutdown;
    static SpGetInfoFn SpGetInfo;
}

static NTSTATUS
InitializeRegistryNotification(VOID);

static NTSTATUS NTAPI
InitializePackage(_In_ ULONG AuthenticationPackageId,
                  _In_ PLSA_DISPATCH_TABLE DispatchTable,
                  _In_opt_ PLSA_STRING Database,
                  _In_opt_ PLSA_STRING Confidentiality,
                  _Out_ PLSA_STRING *AuthenticationPackageName)
{
    LsaAuthenticationPackageId = AuthenticationPackageId;
    LsaDispatchTable = DispatchTable;
    *AuthenticationPackageName = nullptr;

    LSA_STRING APName;
    NTSTATUS Status;

    APName.MaximumLength = sizeof(TKTBRIDGEAP_PACKAGE_NAME_A);
    APName.Length = APName.MaximumLength - sizeof(CHAR);
    APName.Buffer = (PCHAR)TKTBRIDGEAP_PACKAGE_NAME_A;

    Status = DuplicateLsaString(&APName, AuthenticationPackageName);
    NT_RETURN_IF_NTSTATUS_FAILED(Status);

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SpInitialize(_In_ ULONG_PTR PackageId,
             _In_ PSECPKG_PARAMETERS Parameters,
             _In_ PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    NTSTATUS Status;

    DebugTrace(WINEVENT_LEVEL_INFO, L"Initializing TktBridgeAP with package ID %lu", PackageId);

    assert(Parameters != nullptr);
    assert(FunctionTable != nullptr);

    LsaSpFunctionTable = FunctionTable;

    RtlZeroMemory(&SpParameters, sizeof(SpParameters));

    SpParameters.Version      = Parameters->Version;
    SpParameters.MachineState = Parameters->MachineState;
    SpParameters.SetupMode    = Parameters->SetupMode;

    if (Parameters->DomainSid != nullptr) {
        Status = RtlDuplicateSid(&SpParameters.DomainSid, Parameters->DomainSid);
        NT_RETURN_IF_NTSTATUS_FAILED(Status);
    }

    if (Parameters->DomainName.Buffer != nullptr) {
        Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                           &Parameters->DomainName,
                                           &SpParameters.DomainName);
        NT_RETURN_IF_NTSTATUS_FAILED(Status);
    }

    if (Parameters->DnsDomainName.Buffer != nullptr) {
        Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                           &Parameters->DnsDomainName,
                                           &SpParameters.DnsDomainName);
        NT_RETURN_IF_NTSTATUS_FAILED(Status);
    }

    SpParameters.DomainGuid = Parameters->DomainGuid;

    return STATUS_SUCCESS;
}

static VOID
FreeDomainSuffixes(VOID)
{
    if (APDomainSuffixes != nullptr) {
        for (PWSTR *pSuffix = APDomainSuffixes; *pSuffix != nullptr; pSuffix++)
            WIL_FreeMemory(*pSuffix);

        WIL_FreeMemory(APDomainSuffixes);
        APDomainSuffixes = nullptr;
    }
}

static NTSTATUS NTAPI
SpShutdown(VOID)
{
    DebugTrace(WINEVENT_LEVEL_INFO, L"TktBridgeAP shutting down");

    RtlFreeSid(SpParameters.DomainSid);
    RtlFreeUnicodeString(&SpParameters.DomainName);
    RtlFreeUnicodeString(&SpParameters.DnsDomainName);
    RtlZeroMemory(&SpParameters, sizeof(SpParameters));

    APFlags = 0;
    APLogLevel = 0;

    WIL_FreeMemory(APKdcHostName);
    APKdcHostName = nullptr;

    WIL_FreeMemory(APRestrictPackage);
    APRestrictPackage = nullptr;

    FreeDomainSuffixes();

    LsaAuthenticationPackageId = 0;
    LsaDispatchTable = nullptr;
    LsaSpFunctionTable = nullptr;

    EventUnregisterPADL_TktBridgeAP();

    return STATUS_SUCCESS;
}

static SECPKG_FUNCTION_TABLE
TktBridgeAPFunctionTable = {
    .InitializePackage = InitializePackage,
    .Initialize = SpInitialize,
    .Shutdown = SpShutdown,
    .GetInfo = SpGetInfo,
    .PreLogonUserSurrogate = PreLogonUserSurrogate,
    .PostLogonUserSurrogate = PostLogonUserSurrogate
};

extern "C"
TKTBRIDGEAP_API NTSTATUS __cdecl
SpLsaModeInitialize(_In_ ULONG LsaVersion,
                    _Out_ PULONG PackageVersion,
                    _Out_ PSECPKG_FUNCTION_TABLE *ppTables,
                    _Out_ PULONG pcTables)
{
    if (LsaVersion != SECPKG_INTERFACE_VERSION) {
        DebugTrace(WINEVENT_LEVEL_ERROR,
            L"SpLsaModeInitialize: unsupported SPM interface version %08x", LsaVersion);
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
    }

    RTL_OSVERSIONINFOW VersionInfo;

    ZeroMemory(&VersionInfo, sizeof(VersionInfo));
    VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);

    auto Status = RtlGetVersion(&VersionInfo);
    NT_RETURN_IF_NTSTATUS_FAILED_MSG(Status, "Failed to determine OS version");

    if (VersionInfo.dwMajorVersion == 10 && VersionInfo.dwMinorVersion >= 22000)
        APFlags |= TKTBRIDGEAP_FLAG_CLOUD_CREDS;

    *PackageVersion = SECPKG_INTERFACE_VERSION_10;
    *ppTables = &TktBridgeAPFunctionTable;
    *pcTables = 1;

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
        L"SpLsaModeInitialize: SPM version %08x", LsaVersion);

    EventRegisterPADL_TktBridgeAP();
    InitializeRegistryNotification();

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SpGetInfo(_Out_ PSecPkgInfo PackageInfo)
{
    RtlZeroMemory(PackageInfo, sizeof(*PackageInfo));

    PackageInfo->fCapabilities  = SECPKG_FLAG_LOGON;
    PackageInfo->wVersion       = TKTBRIDGEAP_PACKAGE_VERSION;
    PackageInfo->wRPCID         = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken     = 0;
    PackageInfo->Name           = (SEC_WCHAR *)TKTBRIDGEAP_PACKAGE_NAME_W;
    PackageInfo->Comment        = (SEC_WCHAR *)TKTBRIDGEAP_PACKAGE_COMMENT_W;

    return STATUS_SUCCESS;
}

static DWORD
RegistryNotifyChanged(VOID)
{
    DWORD dwResult;
    wil::unique_hkey hKey;

    dwResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TKTBRIDGEAP_REGISTRY_KEY_W,
        0, KEY_QUERY_VALUE, &hKey);
    RETURN_IF_WIN32_ERROR_EXPECTED(dwResult);

    APFlags &= ~(TKTBRIDGEAP_FLAG_USER);
    APFlags |= RegistryGetDWordValueForKey(hKey.get(), L"Flags") & TKTBRIDGEAP_FLAG_USER;
#ifndef NDEBUG
    APFlags |= TKTBRIDGEAP_FLAG_DEBUG;
#endif

    APLogLevel = RegistryGetDWordValueForKey(hKey.get(), L"LogLevel");

    WIL_FreeMemory(APKdcHostName);
    APKdcHostName = RegistryGetStringValueForKey(hKey.get(), L"KdcHostName");

    WIL_FreeMemory(APRestrictPackage);
    APRestrictPackage = RegistryGetStringValueForKey(hKey.get(), L"RestrictPackage");

    FreeDomainSuffixes();
    APDomainSuffixes = RegistryGetStringValuesForKey(hKey.get(), L"DomainSuffixes");

    return ERROR_SUCCESS;
}

static NTSTATUS
InitializeRegistryNotification(VOID)
{
    RegistryNotifyChanged();

    auto watcher = wil::make_registry_watcher_nothrow(HKEY_LOCAL_MACHINE,
        TKTBRIDGEAP_REGISTRY_KEY_W, true, [&](wil::RegistryChangeKind) {
            ::RegistryNotifyChanged();
        });

    RETURN_NTSTATUS_IF_NULL_ALLOC(watcher);

    return STATUS_SUCCESS;
}

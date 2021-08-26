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

PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable = nullptr;

/*
 * Globals
 */

SECPKG_PARAMETERS SpParameters;
static ULONG_PTR LsaAuthenticationPackageId = SECPKG_ID_NONE;
static PLSA_DISPATCH_TABLE LsaDispatchTable = nullptr;

static std::mutex APGlobalsLock;
static std::optional<std::wstring> APKdcHostName;
static std::optional<std::wstring> APRestrictPackage;
static std::vector<std::wstring> APDomainSuffixes;
std::atomic<unsigned long> APFlags = 0;
std::atomic<unsigned long> APLogLevel = 0;

extern "C" {
    static LSA_AP_INITIALIZE_PACKAGE InitializePackage;
    static SpInitializeFn SpInitialize;
    static SpShutdownFn SpShutdown;
    static SpGetInfoFn SpGetInfo;
}

static NTSTATUS
InitializeRegistryNotification(VOID);

static VOID
FreeLsaString(_Inout_ PLSA_STRING pLsaString)
{
    if (pLsaString != nullptr) {
        LsaDispatchTable->FreeLsaHeap(pLsaString->Buffer);
        LsaDispatchTable->FreeLsaHeap(pLsaString);
    }
}

static NTSTATUS
DuplicateLsaString(_In_ PLSA_STRING SourceString,
                   _Out_ PLSA_STRING *pDestinationString)
{
    PLSA_STRING DestinationString = nullptr;

    *pDestinationString = nullptr;

    assert(LsaDispatchTable != nullptr);

    auto cleanup = wil::scope_exit([&] {
        FreeLsaString(DestinationString);
                                   });

    DestinationString = static_cast<PLSA_STRING>(LsaDispatchTable->AllocateLsaHeap(sizeof(LSA_STRING)));
    RETURN_NTSTATUS_IF_NULL_ALLOC(DestinationString);

    DestinationString->Buffer = static_cast<PCHAR>(LsaDispatchTable->AllocateLsaHeap(SourceString->MaximumLength));
    RETURN_NTSTATUS_IF_NULL_ALLOC(DestinationString->Buffer);

    RtlCopyMemory(DestinationString->Buffer, SourceString->Buffer, SourceString->MaximumLength);

    DestinationString->Length = SourceString->Length;
    DestinationString->MaximumLength = SourceString->MaximumLength;

    *pDestinationString = DestinationString;
    DestinationString = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

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

    LSA_STRING APName = {
        .Length = sizeof(TKTBRIDGEAP_PACKAGE_NAME_A) - 1,
        .MaximumLength = sizeof(TKTBRIDGEAP_PACKAGE_NAME_A),
        .Buffer = (PCHAR)TKTBRIDGEAP_PACKAGE_NAME_A,
    };

    auto Status = DuplicateLsaString(&APName, AuthenticationPackageName);
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

    LsaAuthenticationPackageId = PackageId;
    LsaSpFunctionTable = FunctionTable;

    ZeroMemory(&SpParameters, sizeof(SpParameters));

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

static NTSTATUS NTAPI
SpShutdown(VOID)
{
    DebugTrace(WINEVENT_LEVEL_INFO, L"TktBridgeAP shutting down");

    DetachKerbLogonInterposer();

    RtlFreeSid(SpParameters.DomainSid);
    RtlFreeUnicodeString(&SpParameters.DomainName);
    RtlFreeUnicodeString(&SpParameters.DnsDomainName);
    ZeroMemory(&SpParameters, sizeof(SpParameters));

    APKdcHostName.reset();
    APRestrictPackage.reset();
    APDomainSuffixes.clear();
    APFlags = 0;
    APLogLevel = 0;

    LsaAuthenticationPackageId = SECPKG_ID_NONE;
    LsaDispatchTable           = nullptr;
    LsaSpFunctionTable         = nullptr;

    EventUnregisterPADL_TktBridgeAP();

    return STATUS_SUCCESS;
}

static SECPKG_FUNCTION_TABLE
TktBridgeAPFunctionTable = {
    .InitializePackage = InitializePackage,
    .LogonTerminated = LsaApLogonTerminated,
    .Initialize = SpInitialize,
    .Shutdown = SpShutdown,
    .GetInfo = SpGetInfo,
    .PreLogonUserSurrogate = LsaApPreLogonUserSurrogate,
    .PostLogonUserSurrogate = LsaApPostLogonUserSurrogate
};

extern "C"
TKTBRIDGEAP_API NTSTATUS __cdecl
SpLsaModeInitialize(_In_ ULONG LsaVersion,
                    _Out_ PULONG PackageVersion,
                    _Out_ PSECPKG_FUNCTION_TABLE *ppTables,
                    _Out_ PULONG pcTables)
{
    RTL_OSVERSIONINFOW VersionInfo;

    if (LsaVersion != SECPKG_INTERFACE_VERSION) {
        DebugTrace(WINEVENT_LEVEL_ERROR,
            L"SpLsaModeInitialize: unsupported SPM interface version %08x", LsaVersion);
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
    }

    ZeroMemory(&VersionInfo, sizeof(VersionInfo));
    VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);

    auto Status = RtlGetVersion(&VersionInfo);
    NT_RETURN_IF_NTSTATUS_FAILED_MSG(Status, "Failed to determine OS version");

    if (VersionInfo.dwMajorVersion == 10 &&
        (VersionInfo.dwMinorVersion > 0 || VersionInfo.dwBuildNumber >= 22000))
        APFlags |= TKTBRIDGEAP_FLAG_CLOUD_CREDS;

    *PackageVersion = SECPKG_INTERFACE_VERSION_10;
    *ppTables = &TktBridgeAPFunctionTable;
    *pcTables = 1;

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
        L"SpLsaModeInitialize: SPM version %08x", LsaVersion);

    EventRegisterPADL_TktBridgeAP();
    InitializeRegistryNotification();

    Status = AttachKerbLogonInterposer();
    NT_RETURN_IF_NTSTATUS_FAILED_MSG(Status, "Failed to attach Kerberos logon interposer");

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SpGetInfo(_Out_ PSecPkgInfo PackageInfo)
{
    ZeroMemory(PackageInfo, sizeof(*PackageInfo));

    PackageInfo->fCapabilities  = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_LOGON;
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
    wil::unique_hkey hKey;
    std::lock_guard GlobalsLockGuard(APGlobalsLock);

    ULONG Flags = APFlags & ~(TKTBRIDGEAP_FLAG_USER);
    ULONG LogLevel = 0;

    APKdcHostName.reset();
    APRestrictPackage.reset();
    APDomainSuffixes.clear();

    auto dwError = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TKTBRIDGEAP_REGISTRY_KEY_W,
                                0, KEY_QUERY_VALUE, &hKey);
    if (dwError == ERROR_SUCCESS) {
        Flags |= RegistryGetULongValueForKey(hKey, L"Flags") & TKTBRIDGEAP_FLAG_USER;
        LogLevel = RegistryGetULongValueForKey(hKey, L"LogLevel");

        std::wstring KdcHostName;
        if (RegistryGetStringValueForKey(hKey, L"KdcHostName", KdcHostName))
            APKdcHostName.emplace(KdcHostName);

        std::wstring RestrictPackage;
        if (RegistryGetStringValueForKey(hKey, L"RestrictPackage", RestrictPackage))
            APRestrictPackage.emplace(RestrictPackage);

        RegistryGetStringValuesForKey(hKey, L"DomainSuffixes", APDomainSuffixes);
    }

#ifndef NDEBUG
    Flags |= TKTBRIDGEAP_FLAG_DEBUG;
#endif
    APFlags = Flags;
    APLogLevel = LogLevel;

    return dwError;
}

static NTSTATUS
RegistryNotifyChangedNoExcept(VOID)
{
    NTSTATUS Status;

    try {
        Status = RegistryNotifyChanged();
    } catch (std::bad_alloc &e) {
        Status = STATUS_NO_MEMORY;
    } catch (std::exception &e) {
        Status = STATUS_UNHANDLED_EXCEPTION;
    }

    RETURN_NTSTATUS(Status);
}

static NTSTATUS
InitializeRegistryNotification(VOID)
{
    RegistryNotifyChangedNoExcept();

    auto watcher = wil::make_registry_watcher_nothrow(HKEY_LOCAL_MACHINE,
        TKTBRIDGEAP_REGISTRY_KEY_W, true, [&](wil::RegistryChangeKind) {
            RegistryNotifyChangedNoExcept();
        });

    RETURN_NTSTATUS_IF_NULL_ALLOC(watcher);

    return STATUS_SUCCESS;
}

static NTSTATUS
GetConfigValue(std::optional<std::wstring> &ConfigValue,
               std::wstring &Buffer,
               PCWSTR &pValue)
{
    std::lock_guard GlobalsLockGuard(APGlobalsLock);

    pValue = nullptr;

    try {
        if (ConfigValue.has_value()) {
            Buffer = ConfigValue.value();
            pValue = Buffer.c_str();
        }
    } catch (std::bad_alloc &e) {
        RETURN_NTSTATUS(STATUS_NO_MEMORY);
    } catch (std::exception &e) {
        RETURN_NTSTATUS(STATUS_UNHANDLED_EXCEPTION);
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

NTSTATUS
GetKdcHostName(std::wstring &Buffer, PCWSTR &pKdcHostName)
{
    return GetConfigValue(APKdcHostName, Buffer, pKdcHostName);
}

PCWSTR
GetRestrictPackage(std::wstring &Buffer, PCWSTR &pRestrictPackage)
{
    return GetConfigValue(APRestrictPackage, Buffer, pRestrictPackage);
}

bool
IsEnabledDomainSuffix(PCWSTR Suffix,
                      bool &Authoritative)
{
    std::lock_guard GlobalsLockGuard(APGlobalsLock);

    Authoritative = !APDomainSuffixes.empty();

    if (Authoritative) {
        for (auto Iterator = APDomainSuffixes.begin();
             Iterator != APDomainSuffixes.end();
             Iterator++) {
            if (_wcsicmp(Suffix, Iterator->c_str()) == 0)
                return true;
        }
    }

    return false;
}

#ifndef NDEBUG
extern "C"
TKTBRIDGEAP_API void __cdecl
TestEntryPoint(PVOID Unused1, PVOID Unused2, CHAR * Unused3, INT Unused4)
{
    RegistryNotifyChanged();

    DebugTrace(WINEVENT_LEVEL_VERBOSE, L"Flags %08x LogLevel %08x KdcHostName %s RestrictPackage %s",
               APFlags.load(), APLogLevel.load(),
               APKdcHostName.has_value() ? APKdcHostName.value().c_str() : L"<none>",
               APRestrictPackage.has_value() ? APRestrictPackage.value().c_str() : L"<none>");

    if (APDomainSuffixes.empty()) {
        DebugTrace(WINEVENT_LEVEL_VERBOSE, L"No domain suffixes configured");
    } else {
        for (auto Iterator = APDomainSuffixes.begin();
             Iterator != APDomainSuffixes.end();
             Iterator++)
            DebugTrace(WINEVENT_LEVEL_VERBOSE, L"Domain suffix: %s", Iterator->c_str());
    }
}
#endif

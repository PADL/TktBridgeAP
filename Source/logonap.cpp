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
 * Globals
 */

PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable = nullptr;
SECPKG_PARAMETERS SpParameters;
static ULONG_PTR LsaAuthenticationPackageId = SECPKG_ID_NONE;

static std::mutex APGlobalsLock;
static std::optional<std::wstring> APKdcHostName;
static std::optional<std::wstring> APRestrictPackage;
static std::vector<std::wstring> APUPNSuffixes;
std::atomic<unsigned long> APFlags = 0;

static wil::unique_registry_watcher_nothrow RegistryWatcher;

EXTERN_C_START

static SpInitializeFn SpInitialize;
static SpShutdownFn SpShutdown;
static SpGetInfoFn SpGetInfo;

EXTERN_C_END

static _Success_(return == STATUS_SUCCESS) NTSTATUS
InitializeRegistryNotification(VOID);

static _Success_(return == STATUS_SUCCESS) NTSTATUS
InitializeWeakImports(VOID);

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
        Status = DuplicateSid(&SpParameters.DomainSid, Parameters->DomainSid);
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

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS NTAPI
SpShutdown(VOID)
{
    DebugTrace(WINEVENT_LEVEL_INFO, L"TktBridgeAP shutting down");

    DetachKerbLogonDetour();

    WIL_FreeMemory(SpParameters.DomainSid);
    RtlFreeUnicodeString(&SpParameters.DomainName);
    RtlFreeUnicodeString(&SpParameters.DnsDomainName);
    ZeroMemory(&SpParameters, sizeof(SpParameters));

    APKdcHostName.reset();
    APRestrictPackage.reset();
    APUPNSuffixes.clear();
    APFlags = 0;

    RegistryWatcher = nullptr;

    LsaAuthenticationPackageId = SECPKG_ID_NONE;
    LsaSpFunctionTable         = nullptr;

    EventUnregisterTktBridgeAP();

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static SECPKG_FUNCTION_TABLE
TktBridgeAPFunctionTable = {
    .LogonTerminated = LsaApLogonTerminated,
    .Initialize = SpInitialize,
    .Shutdown = SpShutdown,
    .GetInfo = SpGetInfo,
    .AcceptCredentials = SpAcceptCredentials,
    .PreLogonUserSurrogate = LsaApPreLogonUserSurrogate,
    .PostLogonUserSurrogate = LsaApPostLogonUserSurrogate
};

EXTERN_C TKTBRIDGEAP_API NTSTATUS NTAPI
SpLsaModeInitialize(_In_ ULONG LsaVersion,
                    _Out_ PULONG PackageVersion,
                    _Out_ PSECPKG_FUNCTION_TABLE *ppTables,
                    _Out_ PULONG pcTables)
{
    RTL_OSVERSIONINFOW VersionInfo;

    if (LsaVersion != SECPKG_INTERFACE_VERSION) {
        DebugTrace(WINEVENT_LEVEL_ERROR,
            L"SpLsaModeInitialize: unsupported SPM interface version %x", LsaVersion);
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
        L"SpLsaModeInitialize: SPM version %x", LsaVersion);

    EventRegisterTktBridgeAP();
    InitializeRegistryNotification();
    InitializeWeakImports();

    Status = (AttachKerbLogonDetour() == ERROR_SUCCESS) ? STATUS_SUCCESS : STATUS_ENTRYPOINT_NOT_FOUND;
    NT_RETURN_IF_NTSTATUS_FAILED_MSG(Status, "Failed to attach Kerberos logon interposer");

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS NTAPI
SpGetInfo(_Out_ PSecPkgInfo PackageInfo)
{
    ZeroMemory(PackageInfo, sizeof(*PackageInfo));

    PackageInfo->fCapabilities  = SECPKG_FLAG_ACCEPT_WIN32_NAME |
                                  SECPKG_FLAG_NEGOTIABLE        |
                                  SECPKG_FLAG_LOGON;
    PackageInfo->wVersion       = TKTBRIDGEAP_PACKAGE_VERSION;
    PackageInfo->wRPCID         = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken     = 0;
    PackageInfo->Name           = (SEC_WCHAR *)TKTBRIDGEAP_PACKAGE_NAME_W;
    PackageInfo->Comment        = (SEC_WCHAR *)TKTBRIDGEAP_PACKAGE_COMMENT_W;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}


static DWORD
RegistryNotifyChanged(VOID)
{
    wil::unique_hkey hKey;
    std::lock_guard GlobalsLockGuard(APGlobalsLock);

    ULONG Flags = APFlags & ~(TKTBRIDGEAP_FLAG_USER);

    APKdcHostName.reset();
    APRestrictPackage.reset();
    APUPNSuffixes.clear();

    auto dwError = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TKTBRIDGEAP_REGISTRY_KEY_W,
                                0, KEY_QUERY_VALUE, &hKey);
    if (dwError == ERROR_SUCCESS) {
        Flags |= RegistryGetULongValueForKey(hKey, L"Flags") & TKTBRIDGEAP_FLAG_USER;

        std::wstring KdcHostName;
        if (RegistryGetStringValueForKey(hKey, L"KdcHostName", KdcHostName))
            APKdcHostName.emplace(KdcHostName);

        std::wstring RestrictPackage;
        if (RegistryGetStringValueForKey(hKey, L"RestrictPackage", RestrictPackage))
            APRestrictPackage.emplace(RestrictPackage);

        RegistryGetStringValuesForKey(hKey, L"UPNSuffixes", APUPNSuffixes);
    }

#ifndef NDEBUG
    Flags |= TKTBRIDGEAP_FLAG_DEBUG;
#endif
    APFlags = Flags;

    return dwError;
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
RegistryNotifyChangedNoThrow(VOID)
{
    NTSTATUS Status;

    try {
        Status = RegistryNotifyChanged();
    } catch (std::bad_alloc) {
        Status = STATUS_NO_MEMORY;
    } catch (std::exception) {
        Status = STATUS_UNHANDLED_EXCEPTION;
    }

    RETURN_NTSTATUS(Status);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
InitializeRegistryNotification(VOID)
{
    RegistryNotifyChangedNoThrow();

    RegistryWatcher = wil::make_registry_watcher_nothrow(HKEY_LOCAL_MACHINE,
        TKTBRIDGEAP_REGISTRY_KEY_W, true, [&](wil::RegistryChangeKind) {
            RegistryNotifyChangedNoThrow();
        });

    RETURN_NTSTATUS_IF_NULL_ALLOC(RegistryWatcher);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
GetGlobalConfigValue(std::optional<std::wstring> &ConfigValue,
                     std::wstring &Buffer,
                     PCWSTR *pValue)
{
    *pValue = nullptr;

    try {
        std::lock_guard GlobalsLockGuard(APGlobalsLock);

        if (ConfigValue.has_value()) {
            Buffer = ConfigValue.value();
            *pValue = Buffer.c_str();
        }
    } catch (std::bad_alloc) {
        RETURN_NTSTATUS(STATUS_NO_MEMORY);
    } catch (std::exception) {
        RETURN_NTSTATUS(STATUS_UNHANDLED_EXCEPTION);
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

_Success_(return == STATUS_SUCCESS) NTSTATUS
GetKdcHostName(std::wstring &Buffer, PCWSTR *pKdcHostName)
{
    return GetGlobalConfigValue(APKdcHostName, Buffer, pKdcHostName);
}

_Success_(return == STATUS_SUCCESS) NTSTATUS
GetRestrictPackage(std::wstring &Buffer, PCWSTR *pRestrictPackage)
{
    return GetGlobalConfigValue(APRestrictPackage, Buffer, pRestrictPackage);
}

bool
IsEnabledUPNSuffix(PCWSTR Suffix,
                   bool *Authoritative)
{
    try {
        std::lock_guard GlobalsLockGuard(APGlobalsLock);

        *Authoritative = !APUPNSuffixes.empty();

        if (*Authoritative) {
            for (auto Iterator = APUPNSuffixes.begin();
                 Iterator != APUPNSuffixes.end();
                 Iterator++) {
                if (_wcsicmp(Suffix, Iterator->c_str()) == 0)
                    return true;
            }
        }
    } catch (std::exception) {
    }

    return false;
}

typedef SECURITY_STATUS
(SEC_ENTRY *PSSPI_ENCRYPT_AUTH_IDENTITY_EX)(_In_ ULONG Options,
                                            _Inout_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthData);

static PSSPI_ENCRYPT_AUTH_IDENTITY_EX _weak_imp_SspiEncryptAuthIdentityEx;
static PSSPI_ENCRYPT_AUTH_IDENTITY_EX _weak_imp_SspiDecryptAuthIdentityEx;

static _Success_(return == STATUS_SUCCESS) NTSTATUS
InitializeWeakImports(VOID)
{
    HMODULE hSspiCli;

    hSspiCli = GetModuleHandle(L"sspicli.dll");
    if (hSspiCli == nullptr)
        RETURN_NTSTATUS(STATUS_DLL_NOT_FOUND);

    _weak_imp_SspiEncryptAuthIdentityEx =
        reinterpret_cast<PSSPI_ENCRYPT_AUTH_IDENTITY_EX>(GetProcAddress(hSspiCli, "SspiEncryptAuthIdentityEx"));
    _weak_imp_SspiDecryptAuthIdentityEx =
        reinterpret_cast<PSSPI_ENCRYPT_AUTH_IDENTITY_EX>(GetProcAddress(hSspiCli, "SspiDecryptAuthIdentityEx"));

    if (_weak_imp_SspiEncryptAuthIdentityEx == nullptr ||
        _weak_imp_SspiDecryptAuthIdentityEx == nullptr)
        RETURN_NTSTATUS(STATUS_ENTRYPOINT_NOT_FOUND);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

SECURITY_STATUS SEC_ENTRY
SspiEncryptAuthIdentityEx(_In_ ULONG Options,
                          _Inout_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthData)
{
    if (_weak_imp_SspiEncryptAuthIdentityEx == nullptr) {
        if (Options == SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_PROCESS)
            return SspiEncryptAuthIdentity(AuthData);
        else
            return SEC_E_ENCRYPT_FAILURE;
    } else {
        return _weak_imp_SspiEncryptAuthIdentityEx(Options, AuthData);
    }
}

SECURITY_STATUS SEC_ENTRY
SspiDecryptAuthIdentityEx(_In_ ULONG Options,
                          _Inout_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthData)
{
    if (_weak_imp_SspiDecryptAuthIdentityEx == nullptr) {
        if (Options == SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_PROCESS)
            return SspiDecryptAuthIdentity(AuthData);
        else
            return SEC_E_ENCRYPT_FAILURE;
    } else {
        return _weak_imp_SspiDecryptAuthIdentityEx(Options, AuthData);
    }
}

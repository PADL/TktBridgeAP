/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    wil.h

Abstract:

    WIL extensions

Environment:

    Local Security Authority (LSA)

--*/

#pragma once

#undef _LSALOOKUP_
#include <wil/common.h>

#include <wil/resource.h>

#if defined(_WINREG_) && !defined(__WIL_WINREG_) && WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_SYSTEM) && !defined(WIL_KERNEL_MODE)
#define __WIL_WINREG_
typedef wil::unique_any<HKEY, decltype(&::RegCloseKey), ::RegCloseKey> unique_hkey;
#endif // __WIL_WINREG_
#if defined(__WIL_WINREG_) && !defined(__WIL_WINREG_STL) && defined(WIL_RESOURCE_STL)
#define __WIL_WINREG_STL
typedef shared_any<unique_hkey> shared_hkey;
typedef weak_any<shared_hkey> weak_hkey;
#endif // __WIL_WINREG_STL

#include <wil/registry.h>
#include <wil/nt_result_macros.h>

// extensions

namespace wil {

#define RETURN_NTSTATUS_IF_NULL_ALLOC(ptr) __WI_SUPPRESS_4127_S do { if ((ptr) == nullptr) { __RETURN_NTSTATUS_FAIL(STATUS_NO_MEMORY, #ptr); }} __WI_SUPPRESS_4127_E while ((void)0, 0)

    static INLINE VOID
    FreeLsaString(PLSA_STRING pLsaString)
    {
        if (pLsaString != NULL) {
	    LsaDispatchTable->FreeLsaHeap(pLsaString->Buffer);
	    LsaDispatchTable(pLsaString);
        }
    }

    typedef unique_any<PLSA_STRING, decltype(&FreeLsaString), &FreeLsaString> unique_lsa_string;
    typedef unique_any<PSID, decltype(&::RtlFreeSid), ::FreeSid> unique_rtl_sid;
}


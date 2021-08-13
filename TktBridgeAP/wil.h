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
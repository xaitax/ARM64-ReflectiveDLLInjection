# Reflective DLL Injection on Windows ARM64

## Quick Summary / TL;DR

This project demonstrates a functional Proof-of-Concept for Reflective DLL Injection (RDI) on Windows ARM64. Key to this is leveraging the `x18` register to access the Thread Environment Block (TEB) and subsequently the Process Environment Block (PEB), a method confirmed via WinDbg and Microsoft's ARM64 ABI documentation. The PoC, developed and tested on a Surface Pro 11 (ARM64), includes a basic injector and a reflective DLL, adapting Stephen Fewer's original RDI principles to the ARM64 architecture. This work aims to fill a gap in publicly available research for this specific technique on ARM64.

![image](https://github.com/user-attachments/assets/6cedde0f-8092-4031-bf00-020b688f4d74)


## Abstract

Reflective DLL Injection (RDI) is a well-documented technique for loading Dynamic Link Libraries (DLLs) into a process's memory from a memory buffer, bypassing conventional disk-based loading mechanisms. While extensively analyzed and utilized on x86 and x64 Windows architectures, its application and detailed public documentation for the Windows on ARM64 platform have been notably limited, with very little readily accessible research specifically addressing RDI on this architecture. This article details the process of adapting and implementing RDI for ARM64, focusing on the architectural nuances required for self-location and API resolution by the reflective loader. We present key findings from Windows Debugger (WinDbg) analysis regarding ARM64's Thread Environment Block (TEB) and Process Environment Block (PEB) access, and demonstrate a functional proof-of-concept. The implications for offensive security practitioners and defensive strategies on the ARM64 platform are also discussed.

## 1. Introduction

The Windows on ARM64 platform represents a significant and expanding segment of the computing ecosystem. As this architecture gains traction, particularly with devices like my own Surface Pro 11, the need for security researchers and practitioners to understand its low-level behavior and adapt existing tradecraft becomes increasingly critical. Reflective DLL Injection, originally popularized by [Stephen Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection), offers a potent method for stealthy code execution by manually mapping a DLL within a target process's address space. This technique avoids standard Windows loader events associated with disk-based module loading, thereby evading many traditional detection methods.

Despite its utility, publicly available research and tooling for RDI specifically tailored to ARM64 Windows systems are non-existent (as far as I know). While individual components or concepts may have been touched upon, a cohesive, end-to-end public demonstration and explanation of RDI on ARM64 has been elusive. This article aims to contribute to bridging this gap by detailing the necessary architectural adaptations and providing a clear methodology for achieving RDI on this platform. My approach involves leveraging WinDbg for system introspection and constructing an ARM64-specific reflective loader by adapting established RDI principles.

## 2. Background: Reflective DLL Injection Principles

The core of RDI is the `ReflectiveLoader` function, a position-independent code segment exported by the DLL intended for injection. Once the DLL's raw image is written into the target process's memory and execution is transferred to the `ReflectiveLoader` (e.g., via `CreateRemoteThread`), it performs the following critical operations:

1.  **Self-Location:** Determines its own current base address in the target process's memory.
2.  **API Resolution:** Dynamically locates the addresses of essential Windows API functions (e.g., `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `NtFlushInstructionCache`) without relying on its own, yet unprocessed, import table. This typically involves navigating the Process Environment Block (PEB) to find loaded system modules like `kernel32.dll` and `ntdll.dll`.
3.  **Memory Allocation:** Allocates a new, suitably sized memory region within the target process with execute, read, and write (RWX) permissions.
4.  **PE Image Mapping:** Copies its own PE headers and sections from its initial location to the newly allocated memory region.
5.  **Relocation Processing:** Applies any necessary base relocations to correct absolute addresses within its code and data sections, as the new memory region is unlikely to match the DLL's preferred image base.
6.  **Import Address Table (IAT) Resolution:** Parses its own import directory, loads required dependent DLLs using the resolved `LoadLibraryA`, and populates its IAT with the addresses of imported functions obtained via the resolved `GetProcAddress`.
7.  **Execution Transfer:** Calls the DLL's actual entry point (typically `DllMain`) with the `DLL_PROCESS_ATTACH` reason.

The primary challenge in porting RDI to a new architecture like ARM64 lies in the API resolution phase, specifically how the TEB and PEB are accessed to enumerate loaded modules.

## 3. ARM64 Architectural Considerations for PEB Access

On x86 and x64 architectures, the TEB is typically accessed via the `FS` and `GS` segment registers, respectively. The PEB pointer is then found at a fixed offset within the TEB. ARM64 does not utilize segment registers in this manner, necessitating a different approach for locating these critical structures.

This investigation began by consulting official documentation. Microsoft's [Overview of ARM64 ABI conventions](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions?view=msvc-170) provides crucial details regarding the architecture's register usage. Within this documentation, under the "Integer registers" section, a key piece of information is provided for the `x18` register:

> `x18 N/A Reserved platform register: in kernel mode, points to KPCR for the current processor; In user mode, points to TEB`

This statement directly identifies the `x18` register as the user-mode pointer to the Thread Environment Block (TEB) on ARM64. This was the architectural equivalent we were seeking to replace the FS/GS segment register mechanism.

To verify this and determine the subsequent offset to the Process Environment Block (PEB), we utilized the Windows Debugger (WinDbg) attached to an ARM64 user-mode process (Notepad.exe).

The `!teb` WinDbg command confirmed the presence of the TEB and its `PEB Address` field in ARM64 processes:

```text
0:026> !teb
TEB at 000000347f391000
    ...
    PEB Address:          000000347f35a000
    ...
```

With the TEB's base address known (obtainable programmatically via `x18`), further inspection of the TEB structure using `dt ntdll!_TEB <TEB_Address>` revealed the offset of the `ProcessEnvironmentBlock` (PEB pointer) member:

```text
+0x060 ProcessEnvironmentBlock : 0x00000034`7f35a000 _PEB
```

This debugging output, combined with the ABI documentation, confirmed that on ARM64, the PEB pointer can be retrieved by reading the value of the `x18` register (which gives the TEB base) and then dereferencing the memory location `TEB_BASE + 0x60`. ARM64 C/C++ compilers provide [ARM64 intrinsics](https://learn.microsoft.com/en-us/cpp/intrinsics/arm64-intrinsics?view=msvc-170) such as `__readx18qword()` to facilitate access to such registers, enabling the following C code pattern within the reflective loader:

```c
ULONG_PTR uiPeb;
uiPeb = __readx18qword(0x60); // Reads PEB pointer from TEB_BASE (X18) + 0x60
```

## 4. Implementing the ARM64 Reflective Loader

With the PEB access mechanism for ARM64 identified as `__readx18qword(0x60)`, the construction of the `ReflectiveLoader` could proceed, adapting established RDI principles to the ARM64 architecture. The loader is designed as a position-independent function, typically exported by the DLL intended for injection.

Key implementation details include:

- **4.1. Self-Location and Initial API Pointer Acquisition:**
  The loader first determines its own base address in memory. A common technique involves calling a non-inlined function that returns the address of its caller via an intrinsic like `_ReturnAddress()`. Once its own base is known, the loader can parse its own PE headers. The critical `__readx18qword(0x60)` intrinsic is then used to retrieve the PEB address. From the PEB, the loader navigates to `PEB->Ldr->InMemoryOrderModuleList` to begin enumerating loaded system DLLs, primarily seeking `kernel32.dll` and `ntdll.dll`.

- **4.2. Hashing Algorithms for API Resolution:**
  To dynamically resolve API functions without relying on its own (yet unprocessed) import table, hashing is employed. Pre-calculated hash values for essential functions (`LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `NtFlushInstructionCache`) and their respective DLLs (`kernel32.dll`, `ntdll.dll`) are stored within the loader.

  - _Module Name Hashing_: It was found that the hashing algorithm for module names (derived from `UNICODE_STRING.BaseDllName` in the PEB's LDR data) needed to precisely replicate the byte-wise processing and ASCII-centric uppercasing used in many original RDI implementations to match the pre-calculated `KERNEL32DLL_HASH` and `NTDLLDLL_HASH`. The `UNICODE_STRING.Length` field (in bytes) is used as the counter.

    ```c
    // Simplified excerpt of module name hashing within the ReflectiveLoader
    // pEntry is a PLDR_DATA_TABLE_ENTRY_LDR
    // dwModuleHash is the accumulator, ror_dword_loader performs bitwise rotation
    if (pEntry->BaseDllName.Length > 0 && pEntry->BaseDllName.Buffer != NULL) {
        USHORT usCounter = pEntry->BaseDllName.Length; // Length in bytes
        BYTE *pNameByte = (BYTE*)pEntry->BaseDllName.Buffer;

        do {
            dwModuleHash = ror_dword_loader(dwModuleHash);
            if (*pNameByte >= 'a' && *pNameByte <= 'z') { // Byte-level ASCII check
                dwModuleHash += (*pNameByte - 0x20);    // Uppercase if lowercase ASCII
            } else {
                dwModuleHash += *pNameByte;             // Add byte as is
            }
            pNameByte++;
        } while (--usCounter);
        // Compare dwModuleHash with KERNEL32DLL_HASH or NTDLLDLL_HASH
    }
    ```

  - _Function Name Hashing_: Similarly, function names exported by `kernel32.dll` and `ntdll.dll` are iterated, hashed, and compared against target hashes. The effective algorithm for function names often involves a rotation and sum of direct character ASCII values.

        ```c
        // Simplified excerpt of function name hashing within the ReflectiveLoader
        // c points to a char* function name, h is the accumulator
        do {
            h = ror_dword_loader(h); // _rotr based rotation
            h += *c;                 // Sum of ASCII character values
        } while (*++c);
        // Compare h with LOADLIBRARYA_HASH, GETPROCADDRESS_HASH, etc.
        ```

    Once the base addresses of `kernel32.dll` and `ntdll.dll` are found, their export address tables (EATs) are parsed. The `AddressOfNames`, `AddressOfNameOrdinals`, and `AddressOfFunctions` arrays are used in conjunction with the hashing mechanism to locate the Virtual Addresses (VAs) of the required API functions.

- **4.3. Memory Allocation and PE Image Mapping:**
  Using the dynamically resolved pointer to `VirtualAlloc`, the loader allocates a new memory region within the target process. This region is typically marked with `PAGE_EXECUTE_READWRITE` permissions and sized according to `SizeOfImage` from its own PE header. The loader then meticulously copies its own PE headers (`OptionalHeader.SizeOfHeaders`) and each section (`IMAGE_SECTION_HEADER`) from its initial, temporary location in memory to their respective virtual addresses within this newly allocated image base.

- **4.4. Relocation Processing:**
  Since the DLL is unlikely to be loaded at its preferred `OptionalHeader.ImageBase`, base relocations must be processed. The loader calculates the delta between the new actual image base and the preferred image base. It then iterates through the relocation blocks found via the `IMAGE_DIRECTORY_ENTRY_BASERELOC` data directory. For ARM64, `IMAGE_REL_BASED_DIR64` is the predominant relocation type, requiring the 64-bit delta to be added to the value at the specified offset within the image.

  ```c
  // Simplified excerpt of IMAGE_REL_BASED_DIR64 relocation handling
  // uiNewImageBase is the actual base, uiDelta is (uiNewImageBase - pOldNtHeaders->OptionalHeader.ImageBase)
  // pRelocBlock points to the current IMAGE_BASE_RELOCATION block
  // pRelocEntry points to the current IMAGE_RELOC_LDR entry
  if (pRelocEntry[k].type == IMAGE_REL_BASED_DIR64) {
      *(ULONG_PTR*)(uiNewImageBase + pRelocBlock->VirtualAddress + pRelocEntry[k].offset) += uiDelta;
  }
  ```

- **4.5. Import Address Table (IAT) Resolution:**
  The loader parses its own `IMAGE_DIRECTORY_ENTRY_IMPORT` data directory. For each `IMAGE_IMPORT_DESCRIPTOR`, it uses the resolved `LoadLibraryA` to load the required dependent DLL into the target process's address space. Then, for each imported function (iterating through the `OriginalFirstThunk` or `FirstThunk`), it uses the resolved `GetProcAddress` (using either the function name or ordinal) to find the function's address in the now-loaded dependent module. This address is then written into the corresponding entry in the `FirstThunk` array, effectively populating the IAT.

- **4.6. Execution Transfer and Cleanup:**
  Before transferring execution to the DLL's actual entry point (e.g., `PayloadDllMain`), `NtFlushInstructionCache` is called. This is crucial on architectures like ARM where instruction caching might lead to stale instructions being executed after relocations or IAT patching. The call is typically `fnNtFlushInstructionCache((HANDLE)-1, NULL, 0)` to flush the cache for the current process. Finally, the DLL's entry point is called with `DLL_PROCESS_ATTACH` and any parameters passed to the `ReflectiveLoader`.

The remaining steps of the loader, such as detailed PE structure definitions for internal parsing (e.g., `_PEB_LDR_DATA_LDR`, `_LDR_DATA_TABLE_ENTRY_LDR`), are essential for correct navigation and interpretation of process memory but follow established patterns adapted for 64-bit types.

## 5. Experimental Validation

A proof-of-concept was developed consisting of an ARM64 injector executable and an ARM64 reflective DLL. The DLL's `PayloadDllMain` was programmed to display a `MessageBoxA` upon successful loading. The injector, enhanced with a user-friendly banner and the ability to target processes by name or PID, performed the following sequence:

1.  Read the reflective DLL from disk into a memory buffer.
2.  Parsed the DLL's PE structure to locate the file offset of the exported `ReflectiveLoader` function.
3.  Obtained a handle to the target ARM64 process.
4.  Allocated RWX memory in the target process using `VirtualAllocEx`.
5.  Wrote the DLL's buffered image into the allocated remote memory using `WriteProcessMemory`.
6.  Calculated the absolute address of `ReflectiveLoader` within the target process's address space.
7.  Initiated execution of `ReflectiveLoader` via `CreateRemoteThread`.

Successful execution was confirmed by the appearance of the MessageBoxA from the injected DLL. The injector output below demonstrates a successful injection into `chrome.exe` on a Windows 11 ARM64 system (Build 26200):

```text
C:\Users\ah\Documents\GitHub\ReflectiveDLLInjection_ARM64>arm64_injector.exe chrome.exe arm64_rdi.dll
=====================================================================
|          Reflective DLL Injection on Windows ARM64                |
|                           By @xaitax                              |
=====================================================================

 Host Architecture: ARM64
 Host OS: Windows 11 (Build 26200)

 Targeting process name: chrome.exe
 Found PID 20352 for process name 'chrome.exe'
 DLL Path: arm64_rdi.dll
 DLL file size: 6144 bytes
 DLL read into local buffer at: 0x0000024699117260
 ReflectiveLoader file offset: 0x538
 Target process 20352 opened. Handle: 0x00000000000000AC
 Memory allocated in target at: 0x000002BE69740000 (Size: 6144 bytes)
 DLL written to target memory at: 0x000002BE69740000
 Calculated remote ReflectiveLoader: 0x000002BE69740538
 Remote thread created (Handle: 0x00000000000000B0). Waiting...
 Remote thread completed.
 Remote thread exit code: 0x69750000

 Injection process finished.
```

The remote thread exit code (`0x69750000` in this instance, corresponding to `0x000002BE69740000`) represents the base address where the reflective loader successfully mapped the DLL in the target process.

### 6. Code Availability and Compilation

The proof-of-concept code demonstrating the ARM64 Reflective DLL Injection technique discussed in this article, including the injector and the reflective DLL (comprising the loader and payload), is available in this [GitHub repository](https://github.com/xaitax/ARM64-ReflectiveDLLInjection).

To compile this code, an ARM64 C/C++ development environment is required. For Windows, this typically involves using Microsoft Visual Studio with the ARM64 build tools installed. Compilation should be performed from an "ARM64 Native Tools Command Prompt" or a development environment correctly configured for ARM64 cross-compilation.

**Example Compilation Commands (using MSVC `cl.exe`):**

1.  **Compile the Reflective DLL (e.g., `arm64_rdi.dll`):**
    The DLL must export the `ReflectiveLoader` function and link necessary libraries for its payload (e.g., `User32.lib` if `MessageBoxA` is used). The DLL's entry point for the reflective loader will be the payload's `DllMain` (e.g., `PayloadDllMain`).

    ```batch
    cl /LD /Fe:arm64_rdi.dll arm64_dll.c arm64_reflective_loader.c User32.lib /link /ENTRY:PayloadDllMain /DLL
    ```

    - `/LD`: Create a DLL.
    - `/Fe:filename`: Specify the output DLL name.
    - `User32.lib`: Example library for `MessageBoxA`.
    - `/link /ENTRY:functionName`: Sets the DLL's entry point.
    - `/DLL`: Specifies that a DLL is to be built.

2.  **Compile the Injector Executable (e.g., `arm64_injector.exe`):**

    ```batch
    cl arm64_injector.c /Fe:arm64_injector.exe Kernel32.lib
    ```

    - `Kernel32.lib`: Typically linked by default but can be specified for clarity for functions like `CreateFileA`, `OpenProcess`, etc.

Users should adapt these commands based on their specific source file names and project structure. Ensure that the target architecture in the compiler and linker settings is explicitly set to ARM64.

## 7. Conclusion

This research demonstrates that Reflective DLL Injection is a viable and effective technique on the Windows on ARM64 platform. By identifying the ARM64-specific mechanism for TEB/PEB access (`x18` register and `+0x60` offset) and carefully adapting hashing and PE processing logic, a functional RDI implementation was achieved.

As ARM64 Windows systems become more integrated into the computing landscape, both offensive and defensive security practitioners must adapt their tools and methodologies accordingly. While this work provides a foundational proof-of-concept, further development could incorporate more advanced features such as SEH setup and support for a wider range of PE features to create more robust and versatile ARM64 RDI solutions.

## 8. References

- Microsoft Corporation. [Overview of ARM64 ABI conventions](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions?view=msvc-170)
- Microsoft Corporation. [ARM64 intrinsics](https://learn.microsoft.com/en-us/cpp/intrinsics/arm64-intrinsics?view=msvc-170)
- Fewer, Stephen. [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)

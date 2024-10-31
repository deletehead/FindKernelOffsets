#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <Psapi.h>
#include <tchar.h>
#include <ntstatus.h>
#include <initguid.h>

VOID log0(const char log[]) {
    printf("[*] %s\n", log);
    return;
}
VOID log1(const char log[]) {
    printf("[+] %s\n", log);
    return;
}
VOID log2(const char log[]) {
    printf("[-] %s\n", log);
    return;
}

LPVOID GetBaseAddr(LPCWSTR drvname)
{
    LPVOID drivers[1024];
    DWORD cbNeeded;
    int nDrivers, i = 0;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        WCHAR szDrivers[1024];
        nDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < nDrivers; i++) {
            if (GetDeviceDriverBaseName(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0])))
            {
                if (_wcsicmp(szDrivers, drvname) == 0) {
                    return drivers[i];
                }
            }
        }
    }
    else {
        printf("[!] EnumDeviceDrivers failed with error: %d\n", GetLastError());
    }
    return 0;
}

DWORD64 findPspNotifyFunction(LPVOID nofityRoutineFunctionAddress) {
    DWORD64 PspNotifyRoutineAddr;
    for (int i = 0; i < 35; i++) {
        // Check if we have found the `0xe8` call opcode
        if (((PBYTE)nofityRoutineFunctionAddress)[i] == 0xe8) {
            // Extract the next 4 bytes as a signed 32-bit offset
            DWORD relativeOffset = *(PDWORD)((PBYTE)nofityRoutineFunctionAddress + i + 1);

            // Calculate the absolute offset using relativeOffset
            PspNotifyRoutineAddr = (DWORD64)nofityRoutineFunctionAddress + i + 5 + (INT32)relativeOffset;

            return PspNotifyRoutineAddr;
            break;
        }
    }

    return 0;
}

DWORD64 findNotifyArrayOffsetR13(PBYTE pPspNotifyRoutine) {
    DWORD64 offset = 0; 

    // Loop through the function to find the `lea r13, [PspCreateProcessNotifyRoutine]` instruction
    for (int i = 0; i < 0x200; i++) {  // Adjust the loop range if needed
        // Check for `lea r13, [nt!PspCreateProcessNotifyRoutine]` opcode: `4c 8d 2d`
        if (pPspNotifyRoutine[i] == 0x4c && pPspNotifyRoutine[i + 1] == 0x8d && pPspNotifyRoutine[i + 2] == 0x2d) { 
            // Extract the next 4 bytes as a signed 32-bit offset (displacement)
            INT32 relativeOffset = *(INT32*)((PBYTE)pPspNotifyRoutine + i + 3);

            // Calculate the absolute address of PspCreateProcessNotifyRoutine
            offset = (DWORD64)pPspNotifyRoutine + i + 7 + relativeOffset;  // '7' accounts for the instruction size

            return offset;
            break;
        }
    }

    return 0;
}

DWORD64 findNotifyArrayOffsetRCX(PBYTE pPspNotifyRoutine) {
    DWORD64 offset = 0;

    // Loop through the function to find the `lea r13, [PspCreateProcessNotifyRoutine]` instruction
    for (int i = 0; i < 0x200; i++) {  // Adjust the loop range if needed
        // Check for `lea r13, [nt!PspCreateProcessNotifyRoutine]` opcode: `4c 8d 2d`
        if (pPspNotifyRoutine[i] == 0x48 && pPspNotifyRoutine[i + 1] == 0x8d && pPspNotifyRoutine[i + 2] == 0x0d) {
            // Extract the next 4 bytes as a signed 32-bit offset (displacement)
            INT32 relativeOffset = *(INT32*)((PBYTE)pPspNotifyRoutine + i + 3);

            // Calculate the absolute address of PspCreateProcessNotifyRoutine
            offset = (DWORD64)pPspNotifyRoutine + i + 7 + relativeOffset;  // '7' accounts for the instruction size

            return offset;
            break;
        }
    }

    return 0;
}

int main() {
    log1("Finding offsets for ntoskrnl.exe!");
    log0("Getting base address of NT");
    LPVOID nt_base = GetBaseAddr(L"ntoskrnl.exe");
    printf("[+] NT base: %16llx\n", nt_base);
    
    DWORD64 offset = 0;
    LPVOID pSymbol; 
    DWORD64 pPspSetCreateProcessNotifyRoutine; 
    DWORD64 pPspSetCreateThreadNotifyRoutine;
    DWORD64 pPspSetLoadImageNotifyRoutine;
    DWORD64 offset_PspCreateProcessNotifyRoutine; 
    DWORD64 offset_PspCreateThreadNotifyRoutine;
    DWORD64 offset_PspLoadImageNotifyRoutine;

    HMODULE hNtoskrnl = LoadLibraryExA("Ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    printf("[>] NT kernel loaded at: %llx\n", hNtoskrnl);

    // -- GET PspCreateProcessNotifyRoutine array --
    pSymbol = GetProcAddress(hNtoskrnl, "PsSetCreateProcessNotifyRoutine");
    printf("[>] PsSetCreateProcessNotifyRoutine at: %llx\n", pSymbol);
    pPspSetCreateProcessNotifyRoutine = findPspNotifyFunction(pSymbol);
    PBYTE pBytePspSetCreateProcessNotifyRoutine = (PBYTE)pPspSetCreateProcessNotifyRoutine;  // Example address 
    offset = findNotifyArrayOffsetR13(pBytePspSetCreateProcessNotifyRoutine);
    if (offset != 0) {
        offset_PspCreateProcessNotifyRoutine = offset - (DWORD64)hNtoskrnl;
        printf("[+] PspCreateProcessNotifyRoutine array [%llx] offset: %llx\n", offset_PspCreateProcessNotifyRoutine, 
            ((DWORD64)nt_base + offset_PspCreateProcessNotifyRoutine));
    }
    else {
        printf("[-] Offset not found.\n");
    }

    // -- GET PspCreateThreadNotifyRoutine array --
    pSymbol = GetProcAddress(hNtoskrnl, "PsSetCreateThreadNotifyRoutine");
    printf("[>] PsSetCreateThreadNotifyRoutine at: %llx\n", pSymbol);
    pPspSetCreateThreadNotifyRoutine = findPspNotifyFunction(pSymbol);
    PBYTE pBytePspSetCreateThreadNotifyRoutine = (PBYTE)pPspSetCreateThreadNotifyRoutine;  // Example address 
    offset = findNotifyArrayOffsetRCX(pBytePspSetCreateThreadNotifyRoutine);
    if (offset != 0) {
        offset_PspCreateThreadNotifyRoutine = offset - (DWORD64)hNtoskrnl;
        printf("[+] PspCreateThreadNotifyRoutine array [%llx] offset: %llx\n", offset_PspCreateThreadNotifyRoutine,
            ((DWORD64)nt_base + offset_PspCreateThreadNotifyRoutine));
    }
    else {
        printf("[-] Offset not found.\n");
    }

    // --GET PspCreateLoadImageNotifyRoutine array --
    pSymbol = GetProcAddress(hNtoskrnl, "PsSetLoadImageNotifyRoutine");
    printf("[>] PsSetLoadImageNotifyRoutine at: %llx\n", pSymbol);
    pPspSetLoadImageNotifyRoutine = findPspNotifyFunction(pSymbol);
    PBYTE pBytePspSetLoadImageNotifyRoutine = (PBYTE)pPspSetLoadImageNotifyRoutine; 
    offset = findNotifyArrayOffsetRCX(pBytePspSetLoadImageNotifyRoutine);
    if (offset != 0) {
        offset_PspLoadImageNotifyRoutine = offset - (DWORD64)hNtoskrnl;
        printf("[+] PspImageLoadNotifyRoutine array [%llx] offset: %llx\n", offset_PspLoadImageNotifyRoutine,
            ((DWORD64)nt_base + offset_PspLoadImageNotifyRoutine));
    }
    else {
        printf("[-] Offset not found.\n");
    }

    log1("Finished");

    return 0;
}

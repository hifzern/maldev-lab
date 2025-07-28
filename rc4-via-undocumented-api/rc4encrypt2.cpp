// rc4encrypt2.cpp : pake undocumented winapi ges (SystemFunction032)
//

#include <iostream>
#include <Windows.h>

typedef struct
{
    DWORD Length;
    DWORD MaxLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS (NTAPI* fnSystemFunction032) (
    USTRING* Data,
    USTRING* Key
);

 /*
 Helper function SystemFunction032
 pRc4Key- Rc4 key use to encrypt/decrypt
 pPayloadData - Base address of the buffer to encrypt / decrypt
 dwRc4KeySize - Size of pRc4Key (param `)
 sPayloadSize - Size pf pPayloadData (Param2)
 */

BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {
    NTSTATUS STATUS = 0;

    USTRING Data;
    Data.Buffer = pPayloadData;
    Data.Length = sPayloadSize;
    Data.MaxLength = sPayloadSize;

    USTRING Key;
    Key.Buffer = pRc4Key;
    Key.Length = dwRc4KeySize;
    Key.MaxLength = dwRc4KeySize;
    

    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    if (!SystemFunction032) {
        printf("[!] Failed to resolve SystemFunction032 \n");
        return FALSE;
    }

    if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }

    return TRUE;
}

void PrintHex(const char* label, const BYTE* data, DWORD len) {
    printf("%s ", label);
    for (DWORD i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main()
{
    BYTE payload[] = "flag{c0ngr4tz_y0u_4r3_r34l_k1ng}";
    BYTE rc4Key[] = "key123";

    DWORD payloadSize = sizeof(payload) - 1;
    DWORD keySize = sizeof(rc4Key) - 1;

    printf("[*] payload : \n %s \n", payload);

    //encrypt
    if (Rc4EncryptionViaSystemFunc032(rc4Key, payload, keySize, payloadSize))
    {
        printf("[+] enc hex :\n");
        PrintHex(" ", payload, payloadSize);
    }

    //decrypt
    if (Rc4EncryptionViaSystemFunc032(rc4Key, payload, keySize, payloadSize))
    {
        printf("[+] dec :\n %s \n", payload);
    }

    return 0;
}


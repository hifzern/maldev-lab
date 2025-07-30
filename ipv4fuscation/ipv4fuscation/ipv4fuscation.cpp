#include <iostream>
#include <cstdio>

// function takes in 4 raw bytes and return in ipv4
std::string GenerateIpv4(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
    char buffer[16];

    //creating the ipv4 address and saving it into the output variable
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", a, b, c, d);

    return std::string(buffer);
}

//generate the ipv4 output representation of the shellcode
//function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
bool GenerateIpv4Output(const unsigned char* pShellcode, size_t ShellcodeSize) {
    //if the shellcode buffer is null or the size is not a multiple of 4
    if (!pShellcode || ShellcodeSize == 0 || ShellcodeSize % 4 != 0) {
        std::cerr << "[!] Invalid Shellcode Input \n";
        return false;
    }
    size_t count = ShellcodeSize / 4;
    std::cout << "char* Ipv4Arr[" << count << "] = {\n\t";

    // we will read one shellcode byte at a time, when the total is 4, begin generating the ipv4 address
    //the variable c is used to store the number of bytes read. by default starts at 4.

    for (size_t i = 0; i < ShellcodeSize; i += 4) {
        //track the number of bytes read and when they reach 4 we enter this if statement to begin generating the ipv4 address
        std::string ip = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);
        std::cout << "\"" << ip << "\"";
        
        if (i + 4 < ShellcodeSize) {
            std::cout << ",";
        }
        
        if (((i / 4) + 1) % 8 == 0 && (i + 4 < ShellcodeSize)) {
            std::cout << "\n\t";
        }
    }
    std::cout << "\n};\n\n";
    return true;
}

int main()
{
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90, // NOP SLEDS
        0x41, 0x42, 0x43, 0x44, // ABCD
        0x01, 0x02, 0x03, 0x04,
        0x7f, 0x00, 0x00, 0x01 //127.0.0.1
    };

    size_t size = sizeof(shellcode);
    std::cout << "[i] Generating IPV4 Representation of shellcode \n";
    GenerateIpv4Output(shellcode, size);
    return 0;
}
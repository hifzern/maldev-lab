#include <iostream>
#include <Windows.h>

// function takes in 4 raw bytes and return in ipv4
char* GenerateIpv4(int a, int b, int c, int d) {
    unsigned char Output [32];

    //creating the ipv4 address and saving it into the output variable
    sprintf(Output, "%d.%d.%d.%d", a, b, c, d);

    //print output
    printf("[i] Output : %s \n", Output);

    return (char*)Output;
}

//generate the ipv4 output representation of the shellcode
//function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
    //if the shellcode buffer is null or the size is not a multiple of 4
    if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 4 != 0) {
        return FALSE;
    }
    printf("char* Ipv4Array[%d] = { \n\t", (int)(ShellcodeSize / 4));

    // we will read one shellcode byte at a time, when the total is 4, begin generating the ipv4 address
    //the variable c is used to store the number of bytes read. by default starts at 4.

    int c = 4, counter = 0;
    char* IP = NULL;

    for (int i = 0; i < ShellcodeSize; i++) {
        //track the number of bytes read and when they reach 4 we enter this if statement to begin generating the ipv4 address
        if (c == 4) {
            counter++;

            //generate ipv4 address from 5 bytes which begin at i until [i + 3]
            IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);

            if (i == ShellcodeSize - 4) {
                //print the last ipv4 address
                printf("\"%s\", ", IP);
            }
            else {
                //print the ipv4 address
                printf("\"%s\", ", IP);

            }

            c = 1;

            //beautify output
            if (counter % 8 == 0) {
                printf("\n\t");
            }
        }
        else {
            c++;
        }
    }
    printf("\n};\n\n");
    return TRUE;
}

int main()
{
    std::cout << "Hello World!\n";
}
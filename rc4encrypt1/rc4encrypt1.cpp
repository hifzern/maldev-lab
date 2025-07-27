// rc4encrypt1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

typedef struct 
{
    unsigned int i;
    unsigned int j;
    unsigned char s[256];
} Rc4Context;

void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
    unsigned i;
    unsigned j;
    unsigned char temp;

    //check parameter
    if (context == NULL || key == NULL)
        return ERROR_INVALID_PARAMETER;

    //clear context
    context->i = 0;
    context->j = 0;

    //initialize the s array with identity permutation
    for (i = 0, j = 0; i < 256; i++)
    {
        //randomize the permutations using the supplied key
        j = (j + context->s[i] + key[i % length]) % 256;

        //swap the values of s[i] and s[j]
        temp = context->s[i];
        context->s[i] = context->s[j];
        context->s[j] = temp;
    }
}

void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
    unsigned
}


int main()
{
    std::cout << "Hello World!\n";
}
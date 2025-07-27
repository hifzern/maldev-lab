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
        return;

    //clear context
    context->i = 0;
    context->j = 0;

    //initialize the s array
    for (i = 0; i < 256; i++)
    {
        context->s[i] = i;
    }

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
    unsigned char temp;

    //restore context
    unsigned int i = context->i;
    unsigned int j = context->j;
    unsigned char* s = context->s;

    //encrypt loop
    while (length > 0) {
        //adjust indices
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        //swap
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        //check input
        if (input != NULL && output != NULL)
        {
            //xor input with rc4 stream
            *output = *input ^ s[(s[i] + s[j]) % 256];

            //increment pointers
            input++;
            output++;
        }

        //remaining bytes
        length--;
    }
    //save context
    context->i = i;
    context->j = j;
}


int main()
{
    //initialization
    unsigned char plaintext[] = "flag{c0ngratz_y0u_th3_r34l_k1ng}"; //replacement
    unsigned char ciphertext[sizeof(plaintext)];
    Rc4Context ctx = { 0 };

    //key
    unsigned char* key = (unsigned char*)"strongkey"; //replacement
    rc4Init(&ctx, key, strlen((char*) key));

    //encrypt
    rc4Cipher(&ctx, plaintext, ciphertext, sizeof(ciphertext));

    //print
    std::cout << "enc : ";
    for (int i = 0; i < sizeof(plaintext); i++)
        printf("%02X", ciphertext[i]);
    std::cout << std::endl;
}
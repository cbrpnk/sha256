#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SHA256_BLOCK_SIZE 512

int print_hex(uint8_t *data, size_t len)
{
    for(int i=0; i<len; ++i) {
        printf("%02x ", data[i]);
    }
    
    return 0;
}

int calculate_padding_len(size_t len)
{
    // Go up to the next multiple of SHA256_BLOCK_SIZE - 64, we will
    // append a 64 bit length at the end, making the full padded message
    // a multiple of 512
    // TODO Put back - 64
    if(len%SHA256_BLOCK_SIZE == 0) return 0;
    return SHA256_BLOCK_SIZE-(len%SHA256_BLOCK_SIZE);
}

int sha256_hash(uint8_t *input, size_t len)
{
    //uint8_t *padded_input = malloc(strlen(str) + 1);
    //strncpy(input, str, );
    
    // Padding, Add a single 1, then add a bunch of zeros until the length
    // is a multiple of 512 minus 64
    // Calculate padding
    len = 513;
    
    printf("%d\n", calculate_padding_len(len));
    
    //free(input);
    return 0;
}

int main()
{
    char *str = "abcedf";
    return sha256_hash(str, strlen(str));
}

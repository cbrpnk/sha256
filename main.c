#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define SHA256_BLOCK_SIZE 64    // 512 bit

void print_hex(uint8_t *data, size_t len)
{
    for(int i=0; i<len; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void print_bin(uint8_t *data, size_t len)
{
    for(int i=0; i<len; ++i) {
        printf("%d%d%d%d%d%d%d%d ",
            (data[i] & 0x80) >> 7,
            (data[i] & 0x40) >> 6,
            (data[i] & 0x20) >> 5,
            (data[i] & 0x10) >> 4,
            (data[i] & 0x08) >> 3,
            (data[i] & 0x04) >> 2,
            (data[i] & 0x02) >> 1,
            (data[i] & 0x01) >> 0
        );
        if((i+1)%8 == 0) printf("\n");
    }
    printf("\n");
}

uint64_t switch_endian_64(uint64_t val)
{
    return ((val & 0x00000000000000ff) << 56)
         | ((val & 0x000000000000ff00) << 40)
         | ((val & 0x0000000000ff0000) << 24)
         | ((val & 0x00000000ff000000) <<  8)
         | ((val & 0x000000ff00000000) >>  8)
         | ((val & 0x0000ff0000000000) >> 24)
         | ((val & 0x00ff000000000000) >> 40)
         | ((val & 0xff00000000000000) >> 56);
}

unsigned int calculate_zero_padding_len(size_t len)
{
    // TODO Bug, if len is a multiepl of 64, we return 0 and have no
    // space to include the 64 message len
    
    // Go up to the next multiple of SHA256_BLOCK_SIZE - 8, we will
    // append a 64 bit message_length at the end, making the full padded message
    // a multiple of 64
    unsigned int base = SHA256_BLOCK_SIZE - 8;
    if(len%base == 0) return 0;
    return base-(len%base);
}

int sha256_hash(const uint8_t *input, const uint64_t len)
{
    uint64_t blocks_len = len;
    uint8_t *blocks = malloc(blocks_len);
    memcpy(blocks, input, blocks_len);
    
    // Padding, Add a single 1, then add a bunch of zeros until the length
    // is a multiple of SHA256_BLOCK_SIZE (512) minus 64
    // Calculate padding
    
    // Add padding byte
    blocks_len++;
    blocks = realloc(blocks, blocks_len);
    blocks[blocks_len-1] = 0b10000000;
    
    // Add zero padding
    unsigned int zero_padd_len = calculate_zero_padding_len(blocks_len);
    blocks = realloc(blocks, blocks_len + zero_padd_len);
    bzero(blocks+blocks_len, zero_padd_len);
    blocks_len += zero_padd_len;
    
    
    // Add 64 bit big endian message length (Length is counted in bits)
    blocks = realloc(blocks, blocks_len + 8);
    bzero(blocks+blocks_len, 8);
    *((uint64_t *) (blocks+blocks_len)) = switch_endian_64(len*8);   // BUG
    blocks_len += 8;
    
    // DEBUG
    print_bin(blocks, blocks_len);
    
    free(blocks);
    return 0;
}

int main()
{
    char *str = "hello world";
    return sha256_hash(str, strlen(str));
}

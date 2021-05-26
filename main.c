#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define SHA256_BLOCK_SIZE 64    // 512 bit

typedef uint8_t sha256_block[SHA256_BLOCK_SIZE];

// H constants, the first 32 bits of the fractional part of the square root
// of the first 8 prime numbers
const unsigned int H[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// K constants, the first 32 bits of the fractional part of the cube root
// of the first 64 prime numbers
const unsigned int K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void print_hex(uint8_t *data, size_t len)
{
    for(int i=0; i<len; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

static void print_bin8(uint8_t *data, size_t len)
{
    for(int i=0; i<len; ++i) {
        for(int j=7; j>=0; --j) {
            printf("%d", (data[i] >> j) & 1);
        }
        if((i+1)%8 == 0) printf("\n");
        else printf(" ");
    }
}

static void print_bin32(uint32_t *data, size_t len)
{
    for(int i=0; i<len; ++i) {
        for(int j=31; j>=0; --j) {
            printf("%d", (data[i] >> j) & 1);
        }
        if((i+1)%2 == 0) printf("\n");
        else printf(" ");
    }
}

static uint32_t switch_endian_32(uint32_t val)
{
    return ((val & 0x000000ff) << 24)
         | ((val & 0x0000ff00) <<  8)
         | ((val & 0x00ff0000) >>  8)
         | ((val & 0xff000000) >> 24);
}

static uint64_t switch_endian_64(uint64_t val)
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

static uint32_t rotr32(uint32_t val, uint8_t n)
{
    uint32_t dropped = val & (0xffffffff >> (32-n));
    return (val >> n) | (dropped << (32-n));
}

static unsigned int calculate_zero_padding_len(size_t len)
{
    // Go up to the next multiple of SHA256_BLOCK_SIZE - 8, we will
    // append a 64 bit message_length at the end, making the full padded message
    // a multiple of 64
    unsigned int base = SHA256_BLOCK_SIZE - 8;
    if(len%base == 0) return 0;
    return base-(len%base);
}

static void create_padded_blocks(const uint8_t *input, const uint64_t len,
                uint8_t **output, uint64_t *output_len)
{
    //uint64_t blocks_len = len;
    *output_len = len;
    *output = malloc(*output_len);
    memcpy(*output, input, *output_len);
    
    // Add padding byte
    (*output_len)++;
    *output = realloc(*output, *output_len);
    (*output)[(*output_len)-1] = 0b10000000;
    
    // Add zero padding
    unsigned int zero_padd_len = calculate_zero_padding_len(*output_len);
    *output = realloc(*output, *output_len + zero_padd_len);
    bzero(*output+(*output_len), zero_padd_len);
    *output_len += zero_padd_len;
    
    // Add 64 bit big endian message length (Length is counted in bits)
    *output = realloc(*output, *output_len + 8);
    bzero(*output+(*output_len), 8);
    *((uint64_t *) (*output+(*output_len))) = switch_endian_64(len*8);
    *output_len += 8;
}

static void process_block(uint32_t *hash, sha256_block *block)
{
    // Create Message Schedule w
    uint32_t w[64] = {0};
    memcpy(w, block, SHA256_BLOCK_SIZE);
    
    // Turn current data to big endian
    for(int i=0; i<SHA256_BLOCK_SIZE/4; ++i) {
        w[i] = switch_endian_32(w[i]);
    }
    
    // Compute the extra 48 32bit values
    for(int i=16; i<64; ++i) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) % 0x100000000;
    }
    
    // Compression
    uint32_t a = hash[0];
    uint32_t b = hash[1];
    uint32_t c = hash[2];
    uint32_t d = hash[3];
    uint32_t e = hash[4];
    uint32_t f = hash[5];
    uint32_t g = hash[6];
    uint32_t h = hash[7];
    
    for(int i=0; i<64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = (h + s1 + ch + K[i] + w[i]) % 0x100000000;
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a&b) ^ (a&c) ^ (b&c);
        uint32_t temp2 = (s0 + maj) % 0x100000000;
        h = g;
        g = f;
        f = e;
        e = (d+temp1) % 0x100000000;
        d = c;
        c = b;
        b = a;
        a = (temp1+temp2) % 0x100000000;
    }
    
    // Update hash
    hash[0] = (hash[0] + a) % 0x100000000;
    hash[1] = (hash[1] + b) % 0x100000000;
    hash[2] = (hash[2] + c) % 0x100000000;
    hash[3] = (hash[3] + d) % 0x100000000;
    hash[4] = (hash[4] + e) % 0x100000000;
    hash[5] = (hash[5] + f) % 0x100000000;
    hash[6] = (hash[6] + g) % 0x100000000;
    hash[7] = (hash[7] + h) % 0x100000000;
}

int sha256_hash(uint8_t *out, const uint8_t *input, const uint64_t len)
{
    // Create padded blocks
    uint8_t *blocks = NULL;
    uint64_t blocks_len = 0;
    create_padded_blocks(input, len, &blocks, &blocks_len);
    
    // Init hash values
    uint32_t hash[8];
    memcpy(hash, H, sizeof(H));
    
    // Process each block
    size_t block_count = blocks_len / SHA256_BLOCK_SIZE;
    sha256_block *block = (sha256_block *) blocks;
    for(int i=0; i<block_count; ++i) {
        process_block(hash, block+i);
    }
    
    // Turn hash to little endian
    for(int i=0; i<8; ++i) {
        hash[i] = switch_endian_32(hash[i]);
    }
    
    memcpy(out, hash, 32);  // TODO Maybe Use out for intermediate steps
    free(blocks);
    return 0;
}

int main()
{
    char *str = "hello world";
    char hash[32];
    sha256_hash(hash, str, strlen(str));
    print_hex((uint8_t *) hash, 32);
    printf("\n");
    
    return 0;
}

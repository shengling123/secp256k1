#include <stdio.h>
#include "secp256k1.h"
#include <string.h>
#include <sys/syscall.h>
#include <linux/random.h>

int main()
{
    secp256k1_context *content = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const unsigned char seckey[32] = {0};
    syscall(SYS_getrandom, (void*)seckey, 32, 0);

    for(int i = 0; i < 32; i++)
    {
        printf("%02x", seckey[i]);
    }
    printf("\n");
    //const unsigned char seckey[32] = {1,4,6,8,20,2,4,5,6,7,8,3,3,7,8,9,54,8,1,4,6,8,20,2,4,5,6,7,8,3,3,7};
    secp256k1_ec_seckey_verify(content,seckey);
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(content,&pubkey, seckey);

    unsigned char output[72] = {0};
    size_t len = 72;

    secp256k1_ec_pubkey_serialize(content, output, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED | 0);

    
    for(int i = 1; i < 65; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");
    secp256k1_context_destroy(content);
    return 0;
}

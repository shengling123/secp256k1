#include <stdio.h>
#include "include/secp256k1.h"
#include "src/scalar_impl.h"
#include "include/secp256k1_recovery.h"
#include "src/ecmult.h"
#include "src/ecdsa_impl.h"
#include "src/secp256k1.c"
#include "src/modules/recovery/main_impl.h"

#include <string.h>
#include <sys/syscall.h>
#include <linux/random.h>

unsigned char seckey[32] = {0x84,0xab,0xa3,0x82,0x07,0xa3,0xe2,0x06,
                        0x14,0xa3,0x28,0x4b,0x8b,0x04,0x9c,0xe0,
                        0xa0,0x09,0x44,0xa0,0xd6,0x6c,0xd1,0xeb,
                        0xe4,0x3b,0x6f,0x94,0x92,0xcb,0x7b,0x97};
unsigned char pk[64] = {0};
unsigned char msg[32] = {0};
unsigned char output64[65] = {0};

//创建公钥私钥
void create_pv_or_pk(secp256k1_context *content)
{
    //const unsigned char seckey[32] = {0};
    //syscall(SYS_getrandom, (void*)seckey, 32, 0);
    printf("pv = ");
    for(int i = 0; i < 32; i++)
    {
        printf("%02x", seckey[i]);
    }
    printf("\n");
    secp256k1_ec_seckey_verify(content,seckey);
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(content,&pubkey, seckey);

    unsigned char output[72] = {0};
    size_t len = 72;

    secp256k1_ec_pubkey_serialize(content, output, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED | 0);

    
    for(int i = 1; i < 65; i++)
    {
        //printf("%02x", output[i]);
        pk[i-1] = output[i];
    }
    

}

//创建address
void pubkey_to_address()
{
    printf("pk = ");
    for(int i = 0; i < 64; i++)
    {
        printf("%02x", pk[i]);
    }
    printf("\n");
    printf("sender = ");
    unsigned char hash[32] = {0};
    int ret = sha3_256(hash, sizeof(hash), pk, sizeof(pk));
    for(int i = 12; i < 32; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");   
}

//消息sha3处理
void sha3(char *tx)
{
    
    int ret = sha3_256(msg, sizeof(msg), (unsigned char *)tx, strlen(tx));
    printf("message = ");
    for(int i = 0; i < 32; i++)
    {
        printf("%02x", msg[i]);
    }
    printf("\n"); 
}

//消息签名
void sign(const secp256k1_context* ctx)
{
    secp256k1_ecdsa_recoverable_signature sig;
    secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg, seckey, secp256k1_nonce_function_rfc6979, NULL);
    
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output64, &recid, &sig);
    output64[64] = recid;
    printf("sign = [ r = ");
    for(int i = 0; i < 64; i++)
    {
        printf("%02x", output64[i]);
        if(i == 31)
        {
            printf(", s = ");
        }
    }
    printf(" ]\n"); 

}

//从签名中获取公钥

void get_pk_from_sign(const secp256k1_context* ctx)
{
    secp256k1_ecdsa_recoverable_signature sig;
    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, output64, output64[64]);

    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recover(ctx, &pubkey, &sig, msg);

    printf("recover pk = ");
    
    unsigned char output[72] = {0};
    size_t len = 72;

    secp256k1_ec_pubkey_serialize(ctx, output, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED | 0);

    
    for(int i = 1; i < 65; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");
}



int main()
{
    secp256k1_context *content = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    create_pv_or_pk(content);
    pubkey_to_address();
    sha3("abcdefgh");
    sign(content);
    get_pk_from_sign(content);
    secp256k1_context_destroy(content);
    return 0;
}

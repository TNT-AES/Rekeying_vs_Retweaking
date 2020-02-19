#include "TNT_AES.h"

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened){
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

//public API
static void aes128_load_key_and_exp(uint8_t *key, __m128i *rnkey){
    rnkey[0] = _mm_loadu_si128((const __m128i*) key);
    rnkey[1]  = AES_128_key_exp(rnkey[0], 0x01);
    rnkey[2]  = AES_128_key_exp(rnkey[1], 0x02);
    rnkey[3]  = AES_128_key_exp(rnkey[2], 0x04);
    rnkey[4]  = AES_128_key_exp(rnkey[3], 0x08);
    rnkey[5]  = AES_128_key_exp(rnkey[4], 0x10);
    rnkey[6]  = AES_128_key_exp(rnkey[5], 0x20);
    rnkey[7]  = AES_128_key_exp(rnkey[6], 0x40);
    rnkey[8]  = AES_128_key_exp(rnkey[7], 0x80);
    rnkey[9]  = AES_128_key_exp(rnkey[8], 0x1B);
    rnkey[10] = AES_128_key_exp(rnkey[9], 0x36);
}

// Rijndael RC
// 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,
// 0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A,
// 0x2F,0x5E,0xBC,0x63,0xC6,0x97,0x35,0x6A,
// 0xD4,0xB3,0x7D,0xFA,0xEF,0xC5,0x91,0x39,

static void TNT_AES_load_key_and_exp(uint8_t *key, __m128i *rnkey){
    rnkey[ 0] = _mm_loadu_si128((const __m128i*) key);
    rnkey[ 1] = AES_128_key_exp(rnkey[ 0], 0x01);
    rnkey[ 2] = AES_128_key_exp(rnkey[ 1], 0x02);
    rnkey[ 3] = AES_128_key_exp(rnkey[ 2], 0x04);
    rnkey[ 4] = AES_128_key_exp(rnkey[ 3], 0x08);
    rnkey[ 5] = AES_128_key_exp(rnkey[ 4], 0x10);
    rnkey[ 6] = AES_128_key_exp(rnkey[ 5], 0x20);
    rnkey[ 7] = AES_128_key_exp(rnkey[ 6], 0x40);
    rnkey[ 8] = AES_128_key_exp(rnkey[ 7], 0x80);
    rnkey[ 9] = AES_128_key_exp(rnkey[ 8], 0x1B);
    rnkey[10] = AES_128_key_exp(rnkey[ 9], 0x36);
    rnkey[11] = AES_128_key_exp(rnkey[10], 0x6C);
    rnkey[12] = AES_128_key_exp(rnkey[11], 0xD8);
    rnkey[13] = AES_128_key_exp(rnkey[12], 0xAB);
    rnkey[14] = AES_128_key_exp(rnkey[13], 0x4D);
    rnkey[15] = AES_128_key_exp(rnkey[14], 0x9A);
    rnkey[16] = AES_128_key_exp(rnkey[15], 0x2F);
    rnkey[17] = AES_128_key_exp(rnkey[16], 0x5E);
    rnkey[18] = AES_128_key_exp(rnkey[17], 0xBC);
}

static void aes128_enc(__m128i *subkey, uint8_t *plainText, uint8_t *cipherText){
    __m128i m = _mm_loadu_si128((__m128i *) plainText);
    AES_DO_ENC_BLOCK(m, subkey);
    _mm_storeu_si128((__m128i *) cipherText, m);
}

static void TNT_AES_enc(__m128i *subkey, uint8_t *tweakText, uint8_t *plainText, uint8_t *cipherText){
    __m128i m = _mm_loadu_si128((__m128i *) plainText);
    __m128i tk = _mm_loadu_si128((__m128i *) tweakText);
    TNT_AES_DO_ENC_BLOCK(m, subkey, tk);
    _mm_storeu_si128((__m128i *) cipherText, m);
}

void AES_Rekey_ENC(
    uint8_t *cipher,
    uint8_t *plain,
    uint8_t *key,
    size_t mlen
){
    __m128i rnkey[11];

    while (mlen)
    {
        aes128_load_key_and_exp(key, rnkey);
        aes128_enc(rnkey, plain, cipher);

        key += STATE_INBYTES;
        plain += STATE_INBYTES;
        cipher += STATE_INBYTES;
        mlen -= STATE_INBYTES;
    }

}

void TNT_AES_Retweak_ENC(
    uint8_t *cipher,
    uint8_t *plain,
    uint8_t *key,
    uint8_t *tweak,
    size_t mlen
)
{
    __m128i rnkey[ntotal + 1];
    TNT_AES_load_key_and_exp(key, rnkey);

    while (mlen)
    {
        TNT_AES_enc(rnkey, tweak, plain, cipher);

        tweak += STATE_INBYTES;
        plain += STATE_INBYTES;
        cipher += STATE_INBYTES;
        mlen -= STATE_INBYTES;
    }
}
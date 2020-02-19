#ifndef TNT_AES_H__
#define TNT_AES_H__

#include "types.h"

#define n1 6
#define n2 6
#define n3 6
#define ntotal (n1 + n2 + n3)

#define STATE_INBYTES 16
#define KEY_INBYTES 16
#define TWEAK_INBYTES 16

//macros
#define AES_DO_ENC_BLOCK(m, k) \
    do{\
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenclast_si128(m, k[10]);\
    }while(0)

#define TNT_AES_DO_ENC_BLOCK(m, k, t) \
    do{\
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_xor_si128       (m, t    ); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenc_si128    (m, k[10]); \
        m = _mm_aesenc_si128    (m, k[11]); \
        m = _mm_aesenc_si128    (m, k[12]); \
        m = _mm_xor_si128       (m, t    ); \
        m = _mm_aesenc_si128    (m, k[13]); \
        m = _mm_aesenc_si128    (m, k[14]); \
        m = _mm_aesenc_si128    (m, k[15]); \
        m = _mm_aesenc_si128    (m, k[16]); \
        m = _mm_aesenc_si128    (m, k[17]); \
        m = _mm_aesenc_si128    (m, k[18]); \
    }while(0)

void AES_Rekey_ENC(
    uint8_t *cipher,
    uint8_t *plain,
    uint8_t *key,
    size_t mlen
);

void TNT_AES_Retweak_ENC(
    uint8_t *cipher,
    uint8_t *plain,
    uint8_t *key,
    uint8_t *tweak,
    size_t mlen
);

#endif
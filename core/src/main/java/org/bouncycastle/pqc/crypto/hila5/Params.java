package org.bouncycastle.pqc.crypto.hila5;

class Params
{
    static final int N = 1024;
    static final int K = 16; /* used in sampler */
    static final int Q = 12289;
    static final int B = 799;  

    static final int POLY_BYTES = 1792;
    static final int REC_BYTES = 256;
    static final int SEED_BYTES = 32;     // care changing this one - connected to digest size used.
   
/* missing params
#define HILA5_MAX_ITER          100
#define HILA5_KEY_LEN           32
#define HILA5_ECC_LEN           30
#define HILA5_PACKED1           (HILA5_N / 8)
#define HILA5_PACKED14          (14 * HILA5_N / 8)
#define HILA5_PAYLOAD_LEN       (HILA5_KEY_LEN + HILA5_ECC_LEN)
#define HILA5_PUBKEY_LEN        (HILA5_SEED_LEN + HILA5_PACKED14)
#define HILA5_PRIVKEY_LEN       (HILA5_PACKED14 + 32)
#define HILA5_CIPHERTEXT_LEN    (HILA5_PACKED14 + HILA5_PACKED1 + \
                                HILA5_PAYLOAD_LEN + HILA5_ECC_LEN)
*/    
}

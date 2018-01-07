package org.bouncycastle.pqc.crypto.hila5;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA3Digest;

/**
 * This implementation is based heavily on the C reference implementation from https://github.com/mjosaarinen/hila5/.
 */

class Hila5
{
    static final int HILA5_N = 1024;
    static final int HILA5_Q = 12289;
    //    static final int K = 16; /* used in sampler */
    static final int HILA5_B = 799;

    static final int HILA5_MAX_ITER = 100;
    static final int HILA5_SEED_LEN = 32;
    static final int HILA5_KEY_LEN = 32;
    static final int HILA5_ECC_LEN = 30;
    static final int HILA5_PACKED1 = (HILA5_N / 8);
    static final int HILA5_PACKED14 = (14 * HILA5_N / 8);
    static final int HILA5_PAYLOAD_LEN = (HILA5_KEY_LEN + HILA5_ECC_LEN);
    static final int HILA5_PUBKEY_LEN = (HILA5_SEED_LEN + HILA5_PACKED14);
    static final int HILA5_PRIVKEY_LEN = (HILA5_PACKED14 + 32);
    static final int HILA5_CIPHERTEXT_LEN = (HILA5_PACKED14 + HILA5_PACKED1 + HILA5_PAYLOAD_LEN + HILA5_ECC_LEN);


    // temporal   
    public static final int SENDA_BYTES = Params.POLY_BYTES + Params.SEED_BYTES;
    public static final int SENDB_BYTES = Params.POLY_BYTES + Params.REC_BYTES;
    public static final int POLY_SIZE = Params.N;

    // to get random bytes:
    // byte[] seed = new byte[HILA5_SEED_LEN];
    // SecureRandom rand; rand.nextBytes(seed);


    // == Rings and Number Theoratic Transforms ==================================

    static int[] pow1945 = new int[2048];  //powers of g=1945 mod q
    static boolean pow1945_ok = false;  //true after initialization

    public static void init_pow1945()
    {
	if (pow1945_ok)                     // nothing to do then
	    return;

	int x = 1;                          // 1945^0 = 1
	for (int i = 0; i < 2048; i++) {    // 1945^1024 = -1 (mod q)
	    pow1945[i] = x;
	    x = (1945 * x) % HILA5_Q;       // consecutive powers
	}
	pow1945_ok = true;                    // table now ok
    }

    // Scalar multiplication: v = c * v
    // Is v passed by reference? i.e. is it modified?
    public static void smul(int[] v, int c)
    {
	for (int i = 0; i < HILA5_N; i++)
	    v[i] = (c * v[i]) % HILA5_Q;
    }

    // Pointwise multiplication: d = a (*) b.
    public static void vmul(int[] d, int[] a, int[] b)
    {
	for (int i = 0; i < HILA5_N; i++)
	    d[i] = (a[i] * b[i]) % HILA5_Q;
    }

    
    public static void keygen(SecureRandom rand, byte[] send, short[] sk)
    {
	return;
    }

    public static void sharedB(SecureRandom rand, byte[] sharedKey, byte[] send, byte[] received)
    {
	return;
    }

    public static void sharedA(byte[] sharedKey, short[] sk, byte[] received)
    {
	return;
    }

    static void decodeA(short[] pk, byte[] seed, byte[] r)
    {
	return;
    }

    static void decodeA(short[] b, short[] c, byte[] r)
    {
	return;
    }

    static void encodeA(byte[] r, short[] pk, byte[] seed)
    {
	return;
    }

    static void encodeB(byte[] r, short[] b, short[] c)
    {
	return;
    }

        static void generateA(short[] a, byte[] seed)
    {
        //Poly.uniform(a, seed);
	return;
    }
    
    static void sha3(byte[] sharedKey)
    {
        SHA3Digest d = new SHA3Digest(256);
        d.update(sharedKey, 0, 32);
        d.doFinal(sharedKey, 0);
    }
}

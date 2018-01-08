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

    /* C->Java Translation between data types 
       int32_t -> int
       int16_t -> short
       uint32_t -> int
       uint16_t -> short
       unsigned char[] -> byte[]
       char -> byte
       uint8_t -> byte
     */

    /* Original parameters in the C implementation are commented as the first line of the method, for reference */ 


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
    public static void slow_smul(int[] v, int c)
    {
	//(int32_t v[HILA5_N], int32_t c)
	for (int i = 0; i < HILA5_N; i++)
	    v[i] = (c * v[i]) % HILA5_Q;
    }

    // Pointwise multiplication: d = a (*) b.
    public static void slow_vmul(int[] d, int[] a, int[] b)
    {
	//(int32_t d[HILA5_N], const int32_t a[HILA5_N], const int32_t b[HILA5_N])
	for (int i = 0; i < HILA5_N; i++)
	    d[i] = (a[i] * b[i]) % HILA5_Q;
    }

    // Vector addition: d = a + b.
    public static void slow_vadd(int[] d, int[] a, int[] b)
    {
	//(int32_t d[HILA5_N], const int32_t a[HILA5_N], const int32_t b[HILA5_N])
	for (int i = 0; i < HILA5_N; i++)
	    d[i] = (a[i] + b[i]) % HILA5_Q;
    }

    // reverse order of ten bits i.e. 0x200 -> 0x001 and vice versa
    public static int bitrev10(int x)
    {
	//(int32_t x)
	int t;
	
	x &= 0x3FF;                         // 9876543210 original order
	x = (x << 5) | (x >> 5);            // 4321098765 5/5 bit swap
	t = (x ^ (x >> 4)) & 0x021;
	x ^= t ^ (t << 4);                  // 0321458769 outer bit swap
	t = (x ^ (x >> 2)) & 0x042;
	x ^= t ^ (t << 2);                  // 0123456789 inner bit swap
	return x & 0x3FF;
    }

    // Slow polynomial ring multiplication: d = a * b  (mod x^1024 + 1)    
    public static void slow_rmul(int[] d, int[] a, int[] b)
    {
	// (int32_t d[HILA5_N], const int32_t a[HILA5_N], const int32_t b[HILA5_N])
	int x;
	
	for (int i = 0; i < HILA5_N; i++) {
	    x = 0;
	    for (int j = 0; j <= i; j++)            // positive side
		x = (x + a[j] * b[i - j]) % HILA5_Q;
	    for (int j = i + 1; j < HILA5_N; j++)   // negative wraparound
		x = (x - a[j] * b[HILA5_N + i - j]) % HILA5_Q;
	    // Force into positive [0, q-1] range ("constant time" masking)
	    d[i] = x + (-((x >> 31) & 1) & HILA5_Q);
	}
    }    

    // Slow number theoretic transform and scaling: d = c * NTT(v).    
    public static void slow_ntt(int[] d, int[] v, int c)
    {
	// (int32_t d[HILA5_N], const int32_t v[HILA5_N], int32_t c)
	int k, r;
	int x;
	
	for (int i = 0; i < HILA5_N; i++) {
	    r = 2 * bitrev10(i) + 1;        // bit reverse index
	    x = 0;
	    k = 0;
	    for (int j = 0; j < HILA5_N; j++) {
		x = (x + v[j] * pow1945[k]) % HILA5_Q;
		k = (k + r) & 0x7FF;        // k = (j * r) % 2048 next round
	    }
	    d[i] = (c * x) % HILA5_Q;       // multiply with scalar c
	}
    }

// == Encoding and Decoding of Ring Polynomials ==============================

// 14-bit packing; mod q integer vector v[1024] to byte sequence d[1792]
    public static void hila5_pack14(int[] d, int[] v)
    {
	//(uint8_t d[HILA5_PACKED14], const int32_t v[HILA5_N])
	/* Do we lose information by copying a value of v[] into d[]?
	   Change d from byte[] to int[] */
	int x, y;

	for (int i = 0, j = 0; i < HILA5_N;) {
	    x = v[i++];
	    d[j++] = x;
	    y = v[i++];
	    d[j++] = (x >> 8) | (y << 6);
	    d[j++] = y >> 2;
	    x = v[i++];
	    d[j++] = (y >> 10) | (x << 4);
	    d[j++] = x >> 4;
	    y = v[i++];
	    d[j++] = (x >> 12) | (y << 2);
	    d[j++] = y >> 6;
	}
    }

    // 14-bit unpacking; bytes in d[1792] to integer vector v[1024]
    public static void hila5_unpack14(int[] v, byte[] d)
    {
	//(int32_t v[HILA5_N], const uint8_t seed[HILA5_SEED_LEN])
	int x;

	for (int i = 0, j = 0; i < HILA5_N;) {
	    x = d[j++];
	    x |= (((int) d[j++]) << 8);
	    v[i++] = x & 0x3FFF;
	    x >>= 14;
	    x |= (((int) d[j++]) << 2);
	    x |= (((int) d[j++]) << 10);
	    v[i++] = x & 0x3FFF;
	    x >>= 14;
	    x |= (((int) d[j++]) << 4);
	    x |= (((int) d[j++]) << 12);
	    v[i++] = x & 0x3FFF;
	    x >>= 14;
	    x |= (((int) d[j++]) << 6);
	    v[i++] = x;
	}
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

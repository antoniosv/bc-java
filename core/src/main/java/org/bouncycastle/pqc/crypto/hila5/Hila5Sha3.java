package org.bouncycastle.pqc.crypto.hila5;
class Hila5Sha3
{
    public static long ROTL64(long a, int offset)
    {
	return ((a << offset) ^ (a >> (64 - offset)));
    }  
    
    public static void sha3Keccakf(long[] st)
    {
	/*
	// numbers are too large for signed long in java 
	// constants
	Long[] keccakf_rndc = {
	    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};
	int[] keccakf_rotc = {      // Rotation constant
	    1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
	    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
	};
	int keccakf_piln = {      // Pi index
	    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
	    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
	};

	// variables
	int i, j, r;
	long t;
	long[] bc = new long[5];
	
	HILA5_ENDIAN_FLIP64(st, 25);
	
    // actual iteration
    for (r = 0; r < 24; r++) {

        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        //  Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        //  Iota
        st[0] ^= keccakf_rndc[r];
    }

    //HILA5_ENDIAN_FLIP64(st, 25);	
    */
    }
    
    // is it static?
    public static void shake_xof(Hila5Sha3CtxT c)
    {
	c.b[c.pt] ^= 0x1F;
	c.b[c.rsiz - 1] ^= 0x80;
	sha3Keccakf(c.q);
	c.pt = 0;	
    }

    // is it static? It seems that out variable is modified
    // this out parameter is actually a uint8_t buf[2] (two byte) output buffer    
    public static void shake_out(Hila5Sha3CtxT c, short[] out, int length)
    {
	int i, j;
	j = c.pt;
	for (i = 0; i < length; i++) {
	    if (j >= c.rsiz) {
		sha3Keccakf(c.q);
		j = 0;
	    }
	    out[i] = c.b[j++];
	}
	c.pt = j;	
    }
}

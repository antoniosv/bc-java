package org.bouncycastle.pqc.crypto.hila5;
class Hila5Sha3
{
    // public ROTL64

    public static void sha3Keccakf(long[] st)
    {
	
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

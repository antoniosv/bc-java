package org.bouncycastle.pqc.crypto.hila5;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA3Digest;

/**
 * This implementation is based heavily on the C reference implementation from https://github.com/mjosaarinen/hila5/.
 */

class Hila5
{
    private static final boolean STATISTICAL_TEST = false;
    public static final int AGREEMENT_SIZE = 32;
    public static final int POLY_SIZE = Params.N;
    public static final int SENDA_BYTES = Params.POLY_BYTES + Params.SEED_BYTES;
    public static final int SENDB_BYTES = Params.POLY_BYTES + Params.REC_BYTES;

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

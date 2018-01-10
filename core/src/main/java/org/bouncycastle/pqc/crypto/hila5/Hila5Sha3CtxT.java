package org.bouncycastle.pqc.crypto.hila5;
import org.bouncycastle.crypto.digests.SHA3Digest;

/*
  Notes:
  - changed void *out to short[] out
 */

class Hila5Sha3CtxT {
    // translate a union construct (not discriminated unions) to Java... how?
    // state: 
    short[] b; // 8-bit bytes
    long[] q;  // 64-bit words
    int pt, rsiz, mdlen; // these don't overflow

    public int init(Hila5Sha3CtxT[] c, int mdlen)
    {
	// mdlen = hash len, bytes
	return 1;
    }

    public int update(Hila5Sha3CtxT[] c, short[] data, int length)
    {
	return 1;
    }

    public int dofinal(short[] md, Hila5Sha3CtxT[] c)
    {
	return 1;
    }

    // compute a sha3 hash (md) of given byte length from "in"
    public void sha3(short[] in, int inlen, short[] md, int mdlen)
    {
	SHA3Digest d = new SHA3Digest(mdlen);
	//update should take as input the values of (b or q), pt,rsiz,mdlen concatenated somehow
	//d.update(sharedKey, 0, 32);	    
	//d.doFinal(sharedKey, 0);

	// but Hila5 impl. does:
	/*
	  hila5_sha3_init(&sha3, mdlen);
	  hila5_sha3_update(&sha3, in, inlen);
	  hila5_sha3_final(md, &sha3);
	  
	  // clear sensitive
	  hila5_sha3_init(&sha3, 0);
	  
	 */
    }    

    public int shake128Init(Hila5Sha3CtxT[] c)
    {
	return init(c, 16);
    }

    public int shake256Init(Hila5Sha3CtxT[] c)
    {
	return init(c, 32);
    }

    public int shakeUpdate(Hila5Sha3CtxT[] c, short[] data, int length)
    {
	return update(c, data, length);
    }

}

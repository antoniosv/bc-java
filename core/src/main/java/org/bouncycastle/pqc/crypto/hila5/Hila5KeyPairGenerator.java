package org.bouncycastle.pqc.crypto.hila5;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
// temp. needed:
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;


public class Hila5KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{

    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pubData = new byte[Hila5.HILA5_PUBKEY_LEN];
        short[] secData = new short[Hila5.HILA5_PRIVKEY_LEN]; // was short[]

	Hila5.keygen(random, pubData, secData);

        return new AsymmetricCipherKeyPair(new NHPublicKeyParameters(pubData), new NHPrivateKeyParameters(secData));
    }

}

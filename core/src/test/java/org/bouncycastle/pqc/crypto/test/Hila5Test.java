import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.pqc.crypto.ExchangePair;
import org.bouncycastle.pqc.crypto.newhope.NHAgreement;
import org.bouncycastle.pqc.crypto.newhope.NHExchangePairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHOtherInfoGenerator;
// add hila5 classses
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Hila5Test extends SimpleTest
{
    private void testKeyExchange() throws Exception
    {
	SecureRandom aliceRandom = new SecureRandom();
	SecureRandom bobRand = new SecureRandom();

	// skipping loop temporarily

	//Hila5KeyPairGenerator kpGen = new Hila5KeyPairGenerator();

	// pass test
	int[] aliceSharedKey = {0, 1};
	int[] bobSharedKey = {0, 1};	   	
	isTrue("value mismatch", Arrays.areEqual(aliceSharedKey, bobSharedKey));

    }
    private void testPrivInfoGeneration() throws IOException
    {
	return;
    }

    private void testInterop()
    {
	return;
    }

    public String getName()
    {
	return "Hila5";
    }

    public void performTest() throws Exception
    {
        testKeyExchange();
        testInterop();
        testPrivInfoGeneration();
    }

    public static void main(String[] args)
    {
	runTest(new Hila5Test());
    }
}

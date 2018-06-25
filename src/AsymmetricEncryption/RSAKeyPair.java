package AsymmetricEncryption;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAKeyPair {

    private static int keyLength;

    private BigInteger PU;   //公钥
    private BigInteger PR;   //私钥


    private BigInteger p;   //素数p
    private BigInteger q;   //素数q
    private BigInteger phiN;//φ(n)=(p-1)(q-1)
    public BigInteger n;    //n=pq

    private static final BigInteger bigOne = BigInteger.ONE;    //大整数的数字“1”

    private static final SecureRandom random = new SecureRandom();  //随机流


    public RSAKeyPair(int N) {
        keyLength = N;
        generateKeyPair();
    }

    private void generateKeyPair(){
        int pLen = (keyLength + 1) >> 1;
        int qLen = keyLength - pLen;

        p = BigInteger.probablePrime(pLen, random);
        PU = new BigInteger("65537");
        while (true) {
            q = BigInteger.probablePrime(qLen, random);
            n = p.multiply(q);
            if (n.bitLength() < keyLength) {
                continue;
            }
            phiN = (p.subtract(bigOne)).multiply(q.subtract(bigOne));
            if (PU.gcd(phiN).equals(bigOne)) {
                break;
            }
        }

        PR = PU.modInverse(phiN);
    }

    public BigInteger[] getPrivate(){
        BigInteger[] key = {PR, n};
        return key;
    }

    public BigInteger[] getPublic(){
        BigInteger[] key = {PU, n};
        return key;
    }

}

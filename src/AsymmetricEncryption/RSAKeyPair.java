package AsymmetricEncryption;

import java.math.BigInteger;

public class RSAKeyPair {

    private static int keyLength;

    private BigInteger PU;   //公钥
    private BigInteger PR;   //私钥


    private BigInteger p;   //素数p
    private BigInteger q;   //素数q
    private BigInteger phiN;//φ(n)=(p-1)(q-1)
    public BigInteger n;    //n=pq

    public RSAKeyPair(int N) {
        keyLength = N;
        generateKeyPair();
    }

    public BigInteger[] getPrivate(){

    }

    public BigInteger[] getPublic(){

    }

}

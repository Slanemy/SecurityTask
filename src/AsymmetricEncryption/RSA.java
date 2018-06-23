package AsymmetricEncryption;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class RSA {


    private static final int BLOCKSIZE = N / 8 - 11;

    private static final byte[] PADDINGM01 = {
            0x00, 0x01,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            0x00
    };

    private byte[] PADDINGM02 = new byte[11];




    private static final BigInteger bigOne = BigInteger.ONE;    //大整数的数字“1”

    private static final SecureRandom random = new SecureRandom();  //随机流

    /**
     * 构造函数，生成素数p,q,大整数n及其欧拉函数
     */
    public RSA() {

        int pLen = (N + 1) >> 1;
        int qLen = N - pLen;

        p = BigInteger.probablePrime(pLen, random);
        PU = new BigInteger("65537");
        while (true) {
            q = BigInteger.probablePrime(qLen, random);
            n = p.multiply(q);
            if (n.bitLength() > N) {
                continue;
            }
            phiN = (p.subtract(bigOne)).multiply(q.subtract(bigOne));
            if (PU.gcd(phiN).equals(bigOne)) {
                break;
            }
        }

        PR = PU.modInverse(phiN);

    }


    /**
     * 加密函数,参考RFC2313标准进行字节填充
     *
     * @param input 明文
     * @return 密文
     */
    public byte[] encrypt(byte[] input, String mode) {
        int inputLen = input.length;
        BigInteger tempKey = BigInteger.ZERO;
        byte[] tempInput = new byte[inputLen + 11];
        byte[] output;
        if (mode.equals("public")) {
            PADDINGM02[0] = 0x00;
            PADDINGM02[1] = 0x02;
            byte[] temp = new byte[8];
            Random r = new Random();
            r.nextBytes(temp);
            System.arraycopy(temp, 0, PADDINGM02, 2, 8);
            PADDINGM02[10] = 0x00;

            System.arraycopy(PADDINGM02, 0, tempInput, 0, 11);
            tempKey = PU;
        } else if (mode.equals("private")) {
            System.arraycopy(PADDINGM01, 0, tempInput, 0, 11);
            tempKey = PR;
        }

        System.arraycopy(input, 0, tempInput, 11, inputLen);

        BigInteger message = new BigInteger(tempInput);
        output = message.modPow(tempKey, n).toByteArray();

        return output;

    }

    /**
     * 解密函数
     *
     * @param input 密文
     * @return 明文
     */
    public byte[] decrypt(byte[] input, String mode) {
        BigInteger cipher = new BigInteger(input);

        byte[] temp = {};
        if (mode.equals("public")) {
            temp = cipher.modPow(PR, n).toByteArray();
            if (temp[0] != 0x02) {
                System.out.println("Error");
            }
        } else if (mode.equals("private")) {
            temp = cipher.modPow(PU, n).toByteArray();
            if (temp[0] != 0x01) {
                System.out.println("Error");
            }
        }

        byte[] output = new byte[temp.length - 10];

        System.arraycopy(temp, 10, output, 0, temp.length - 10);
        return output;
    }

    private static void printByteArray(byte[] input) {
        for (int i = 0; i < input.length; i++) {
            System.out.print(Integer.toHexString(input[i] & 0xff) + " ");
        }
        System.out.println();
    }

    public static void main(String[] args) throws Exception {
        RSA rsa = new RSA();
        String data = "1024位的证书，加密时最大支持117个字节，解密时为128；";
        byte[] test = data.getBytes();
        System.out.println(test.length);
        System.out.print("message:");
        printByteArray(test);
        byte[] cipher = rsa.encrypt(test, "private");
        System.out.print("cipher:");
        printByteArray(cipher);
        byte[] message = rsa.decrypt(cipher, "private");
        System.out.print("message:");
        String t = new String(message);
        printByteArray(message);
        System.out.println(t);

    }
}

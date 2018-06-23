package AsymmetricEncryption;

import java.math.BigInteger;
import java.util.Random;

public class RSA {


    private static final byte[] PADDINGM01 = {
            0x00, 0x01,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            0x00
    };

    private byte[] PADDINGM02 = new byte[11];

    /**
     * 构造函数，生成素数p,q,大整数n及其欧拉函数
     */
    public RSA() {

    }


    /**
     * 加密函数,参考RFC2313标准进行字节填充
     *
     * @param input 明文
     * @return 密文
     */
    public byte[] encrypt(byte[] input, BigInteger[] key, String mode) {
        int inputLen = input.length;
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
        } else if (mode.equals("private")) {
            System.arraycopy(PADDINGM01, 0, tempInput, 0, 11);
        }

        System.arraycopy(input, 0, tempInput, 11, inputLen);

        BigInteger message = new BigInteger(tempInput);
        output = message.modPow(key[0], key[1]).toByteArray();

        return output;

    }

    /**
     * 解密函数
     *
     * @param input 密文
     * @return 明文
     */
    public byte[] decrypt(byte[] input, BigInteger[] key, String mode) {
        BigInteger cipher = new BigInteger(input);

        byte[] temp = cipher.modPow(key[0], key[1]).toByteArray();;
        if (mode.equals("public")) {
            if (temp[0] != 0x02) {
                System.out.println("Error");
            }
        } else if (mode.equals("private")) {
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

        RSAKeyPair keyPair = new RSAKeyPair(1024);
        BigInteger[] publicKey = keyPair.getPublic();
        BigInteger[] privateKey = keyPair.getPrivate();

        byte[] cipher = rsa.encrypt(test,privateKey, "private");
        System.out.print("cipher:");
        printByteArray(cipher);
        byte[] message = rsa.decrypt(cipher,publicKey, "private");
        System.out.print("message:");
        String t = new String(message);
        printByteArray(message);
        System.out.println(t);

    }
}

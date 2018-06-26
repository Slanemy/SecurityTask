package AsymmetricEncryption;


import java.math.BigInteger;
import java.security.SecureRandom;


public class RSA {

    private int PADDING_LENGTH;

    private byte[] PADDING;

    public int BLOCK_SIZE;

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
    private byte[] encryptCore(byte[] input, BigInteger[] key, String mode) {
        int inputLen = input.length;
        PADDING_LENGTH = BLOCK_SIZE - inputLen;
        PADDING = new byte[PADDING_LENGTH];
        byte[] output = new byte[BLOCK_SIZE];
        byte[] tempInput = new byte[inputLen + PADDING_LENGTH];
        if (mode.equals("public")) {
            PADDING[0] = 0x00;
            PADDING[1] = 0x02;
            int tempLen = PADDING_LENGTH - 3;
            int index = 2;
            byte[] temp = new byte[PADDING_LENGTH + 5];  //预留长度防止出现随机数0
            SecureRandom r = new SecureRandom();
            r.nextBytes(temp);
            for (int i = 0; i < temp.length && tempLen > 0; i++) {
                if (temp[i] != 0) {
                    PADDING[index++] = temp[i];
                    tempLen--;
                }
            }
        } else if (mode.equals("private")) {
            PADDING[0] = 0x00;
            PADDING[1] = 0x01;
            for (int i = 2; i < PADDING_LENGTH - 1; i++) {
                PADDING[i] = (byte) 0xff;
            }
        }
        PADDING[PADDING_LENGTH - 1] = 0x00;
        System.arraycopy(PADDING, 0, tempInput, 0, PADDING_LENGTH);
        System.arraycopy(input, 0, tempInput, PADDING_LENGTH, inputLen);

        BigInteger message = new BigInteger(1, tempInput);
        byte[] tempOutput = message.modPow(key[0], key[1]).toByteArray();

        if (tempOutput.length < BLOCK_SIZE) {
            for (int i = 0; i < BLOCK_SIZE - tempOutput.length; i++) {
                output[i] = 0x00;
            }
            System.arraycopy(tempOutput, 0, output, BLOCK_SIZE - tempOutput.length, tempOutput.length);
        } else if (tempOutput.length > BLOCK_SIZE) {
            System.arraycopy(tempOutput, 1, output, 0, BLOCK_SIZE);
        } else {
            System.arraycopy(tempOutput, 0, output, 0, BLOCK_SIZE);
        }

        return output;

    }

    /**
     * 解密函数
     *
     * @param input 密文
     * @return 明文
     */
    private byte[] decryptProcess(byte[] input, BigInteger[] key, String mode) {

        BigInteger cipher = new BigInteger(1, input);

        byte[] temp = cipher.modPow(key[0], key[1]).toByteArray();

        if (mode.equals("public")) {
            if (temp[0] != 0x02) {
                System.out.println("Error");
            }
        } else if (mode.equals("private")) {
            if (temp[0] != 0x01) {
                System.out.println("Error");
            }
        }

        int i = 0;
        for (; i < temp.length; i++) {
            if (temp[i] == 0x00) {
                break;
            }
        }

        byte[] output = new byte[temp.length - i - 1];
        System.arraycopy(temp, i + 1, output, 0, temp.length - i - 1);


        return output;
    }

    public byte[] encrypt(byte[] input, BigInteger[] key, String mode) {
        BLOCK_SIZE = (int) Math.ceil(key[1].bitLength() / 8);

        int offset = 0;
        int partLen = BLOCK_SIZE - 11;
        int len = input.length;


        byte[] output = new byte[(BLOCK_SIZE) * (int) Math.ceil((double) len / partLen)];

        for (; len - partLen * offset > 0; offset++) {
            byte[] tempIn;
            if (len - partLen * (offset + 1) < 0) {
                tempIn = new byte[len - partLen * offset];
                System.arraycopy(input, offset * partLen, tempIn, 0, len - partLen * offset);
            } else {
                tempIn = new byte[partLen];
                System.arraycopy(input, offset * partLen, tempIn, 0, partLen);
            }
            byte[] tempO = encryptCore(tempIn, key, mode);

            System.arraycopy(tempO, 0, output, (BLOCK_SIZE) * offset, BLOCK_SIZE);
        }

        return output;
    }

    public byte[] decrypt(byte[] input, BigInteger[] key, String mode) {
        int lenD = input.length / BLOCK_SIZE;
        byte[] temp = new byte[lenD * BLOCK_SIZE];
        int realLen = 0;
        int offSet = 0;
        for (int i = 0; i < lenD; i++) {
            byte[] tempIn = new byte[BLOCK_SIZE];
            System.arraycopy(input, i * (BLOCK_SIZE), tempIn, 0, BLOCK_SIZE);

            byte[] tempO = decryptProcess(tempIn, key, mode);
            System.arraycopy(tempO, 0, temp, offSet, tempO.length);
            offSet += tempO.length;
            realLen += tempO.length;
        }

        byte[] output = new byte[realLen];
        System.arraycopy(temp, 0, output, 0, realLen);
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
        String data = "1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；1024位的证书，加密时最大支持117个字节，解密时为128；";
        byte[] test = data.getBytes();
        System.out.print("message:");
        printByteArray(test);

        RSAKeyPair keyPair = new RSAKeyPair(1024);
        BigInteger[] publicKey = keyPair.getPublic();
        BigInteger[] privateKey = keyPair.getPrivate();

        int count = 0;
        for (int i = 0; i < 20; i++) {
            byte[] cipher = rsa.encrypt(test, publicKey, "public");
            byte[] message = rsa.decrypt(cipher, privateKey, "public");

            String M = new String(message);
            if(M.equals(data)){
                count++;
            }
        }

        System.out.println(count);

        count = 0;
        for (int i = 0; i < 20; i++) {
            byte[] cipher = rsa.encrypt(test, privateKey, "private");
            byte[] message = rsa.decrypt(cipher, publicKey, "private");

            String M = new String(message);
            if(M.equals(data)){
                count++;
            }
        }

        System.out.println(count);


    }
}

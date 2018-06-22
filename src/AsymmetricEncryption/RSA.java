package AsymmetricEncryption;

import com.sun.deploy.util.ArrayUtil;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class RSA {

    private static final int N = 1024;
    private static final int BLOCKSIZE = N / 8 - 11;

    private static final byte[] PADDINGM01 = {
            0x00, 0x01,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            0x00
    };

    private byte[] PADDINGM02 = new byte[11];


    public BigInteger PU;   //公钥
    public BigInteger PR;   //私钥


    private BigInteger p;   //素数p
    private BigInteger q;   //素数q
    private BigInteger phiN;//φ(n)=(p-1)(q-1)
    public BigInteger n;    //n=pq

    private static final BigInteger bigOne = BigInteger.ONE;    //大整数的数字“1”

    private static final SecureRandom random = new SecureRandom();  //随机流

    /**
     * 构造函数，生成素数p,q,大整数n及其欧拉函数
     */
    public RSA() {
        p = BigInteger.probablePrime(N, random);
        q = BigInteger.probablePrime(N, random);
        n = p.multiply(q);
        phiN = (p.subtract(bigOne)).multiply(q.subtract(bigOne));

        PU = new BigInteger("65537");
        PR = PU.modInverse(phiN);

    }


    /**
     * 加密函数,参考RFC2313标准进行字节填充
     *
     * @param input 明文
     * @return 密文
     */
    public byte[] encrypt(byte[] input, String mode) {
        int partLen = input.length;
        int offset = 0;
        BigInteger tempKey = BigInteger.ZERO;
        byte[] output;
        if (mode.equals("public")) {
            PADDINGM02[0] = 0x00;
            PADDINGM02[1] = 0x02;
            byte[] temp = new byte[8];
            Random r = new Random();
            r.nextBytes(temp);
            System.arraycopy(temp, 0, PADDINGM02, 2, 8);
            PADDINGM02[10] = 0x00;

            tempKey = PU;
        } else if (mode.equals("private")) {
            tempKey = PR;
        }
        for (int i = 0; partLen > 0; i++) {
            byte[] cache = new byte[BLOCKSIZE + 11];
            if (partLen < BLOCKSIZE) {
                byte[] temp = new byte[input.length + 1];
                System.arraycopy(input, 0, temp, 1, input.length);
                temp[0] = 0x00;
                BigInteger message = new BigInteger(temp);

            }

        }

        return new byte[1];


    }

    /**
     * 解密函数，去除为了防止产生负数在输入的字节数组补上的0x01
     *
     * @param input 密文
     * @return 明文
     */
    public byte[] decrypt(byte[] input) {
        BigInteger cipher = new BigInteger(input);
        byte[] temp = cipher.modPow(PR, n).toByteArray();
        byte[] output = new byte[temp.length - 1];
        System.arraycopy(temp, 1, output, 0, temp.length - 1);
        return output;
    }

    private static void printByteArray(byte[] input) {
        for (int i = 0; i < input.length; i++) {
            System.out.print(Integer.toHexString(input[i] & 0xff) + " ");
        }
        System.out.println();
    }

    public static void main(String[] args) throws Exception {
        RSA test = new RSA();
        BigInteger e = new BigInteger("65537");
        String data = "assssssssssssss2156ssssssssss./ssssssss中ssssssss撒打算打算到干哈大公鸡噢isad金佛爱神的箭佛牌大家撒房间爱上的开了房间爱快乐圣诞节佛奥倒计时佛教奥德赛佛教大街上反复ISD哈市将打火机ask打火机卡圣诞节卡仕达杰卡斯ssssssss";
        System.out.print("message:");
        printByteArray(data.getBytes());
        byte[] cipher = test.encrypt(data.getBytes());
        System.out.print("cipher:");
        printByteArray(cipher);
        byte[] message = test.decrypt(cipher);
        System.out.print("message:");
        String t = new String(message);
        printByteArray(message);
        System.out.println(t);
    }
}

package AsymmetricEncryption;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

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
     *
     * @param N 大素数的比特数
     */
    public RSA(int N) {
        p = BigInteger.probablePrime(N, random);
        q = BigInteger.probablePrime(N, random);
        n = p.multiply(q);
        phiN = (p.subtract(bigOne)).multiply(q.subtract(bigOne));

        System.out.println("phiN=" + phiN);
    }

    /**
     * 生成公私钥对，检测公钥是否与φ(n)互素
     *
     * @param e 公钥
     */
    public void generateKey(BigInteger e) {
        if (phiN.gcd(e).equals(bigOne)) {
            PU = e;
            PR = PU.modInverse(phiN);
        } else {
            System.out.println("phiN=" + phiN + ", please re-input correct public key satisfy gcd(PU,phiN)=1");
        }
    }

    /**
     * 加密函数，为了防止产生负数，在输入的字节数组的第一个补上0x01
     * @param input 明文
     * @return 密文
     */
    public byte[] encrypt(byte[] input) {
        byte[] temp = new byte[input.length + 1];
        System.arraycopy(input, 0, temp, 1, input.length);
        temp[0] = 0x01;
        BigInteger message = new BigInteger(temp);
        return message.modPow(PU, n).toByteArray();
    }

    /**
     * 解密函数，去除为了防止产生负数在输入的字节数组补上的0x01
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
        RSA test = new RSA(800);
        BigInteger e = new BigInteger("65537");
        test.generateKey(e);
        String data = "撒打算教奥德赛佛教大街上反复ISD哈市将打火机ask打火机卡圣诞节卡仕达杰卡斯ssssssss";
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

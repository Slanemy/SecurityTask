package Application;


import AsymmetricEncryption.RSA;
import AsymmetricEncryption.RSAKeyPair;
import Hash.MD5;
import Hash.SHA224_256;
import Hash.SHA384_512;
import SymmetricEncryption.AES;
import SymmetricEncryption.DES;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Process {

    private String symAlg;
    private String symKeyType;
    private int seedLength;
    private String hashAlg;
    private int RSABitLength;

    private byte[] symKey;
    private int symKeyLen;
    private BigInteger[] puA;
    private BigInteger[] puB;
    private BigInteger[] prA;
    private BigInteger[] prB;

    private Date day = new Date();
    SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public Process() {
    }

    public void initialize(String symAlg, String symKeyType, String seed, String hashAlg, String RSABitLength) {
        this.hashAlg = hashAlg;
        this.RSABitLength = Integer.valueOf(RSABitLength);
        if (!seed.equals("")) {
            this.seedLength = Integer.valueOf(seed);
        }
        this.symKeyType = symKeyType;
        this.symAlg = symAlg;
    }

    private static void printByteArray(byte[] input) {
        for (int i = 0; i < input.length; i++) {
            System.out.print(Integer.toHexString(input[i] & 0xff) + " ");
        }
        System.out.println();
    }

    private static String bytes2String(byte[] input) {
        String out = "";
        for (int i = 0; i < input.length; i++) {
            out += Integer.toHexString(input[i] & 0xff);
        }
        return out;
    }

    public void generateKeys() {
        symKeyLen = symAlg.equals("DES") ? 8 : 16;
        symKey = new byte[symKeyLen];
        SecureRandom random = new SecureRandom();

        if (symKeyType.equals("bySeed")) {
            byte[] seeds = SecureRandom.getSeed(seedLength);
            random.setSeed(seeds);
        }
        random.nextBytes(symKey);

        RSAKeyPair keyPairA = new RSAKeyPair(RSABitLength);
        puA = keyPairA.getPublic();
        prA = keyPairA.getPrivate();

        RSAKeyPair keyPairB = new RSAKeyPair(RSABitLength);
        puB = keyPairB.getPublic();
        prB = keyPairB.getPrivate();
    }

    public String getInitInfo(String user) {
        StringBuilder info = new StringBuilder();
        info.append("\n---------------------------------------------------" + df.format(day) + "---------------------------------------------------\n");
        info.append("-----------------------------------------------------------初始化-----------------------------------------------------------\n");
        if (user.equals("A")) {
            info.append("使用的对称加密算法：" + symAlg + "\n");
            info.append("使用的对称密钥：" + bytes2String(symKey) + "\n");
            info.append("发送方公钥：（" + puA[0] + "，" + puA[1] + "）\n");
            info.append("发送方私钥：（" + prA[0] + "，" + prA[1] + "）\n");
            info.append("使用的数字签名算法：" + hashAlg + "\n");
        } else {
            info.append("接收方公钥：（" + puB[0] + "，" + puB[1] + "）\n");
            info.append("接收方私钥：（" + prB[0] + "，" + prB[1] + "）\n");
        }
        info.append("-----------------------------------------------------------------------------------------------------------------------------\n");

        return info.toString();
    }

    public byte[] getSignature(byte[] inputBytes) {
        RSA rsa = new RSA();
        return rsa.encrypt(inputBytes, prA, "private");
    }

    public byte[] getHash(byte[] inputBytes) {
        byte[] outputBytes = {};
        if (hashAlg.equals("MD5")) {
            MD5 md5 = new MD5();
            outputBytes = md5.getMD5Str(inputBytes);
        } else if (hashAlg.equals("SHA224")) {
            SHA224_256 sha224 = new SHA224_256("SHA224");
            sha224.update(inputBytes);
            outputBytes = sha224.getSHAStr();
        } else if (hashAlg.equals("SHA256")) {
            SHA224_256 sha256 = new SHA224_256("SHA256");
            sha256.update(inputBytes);
            outputBytes = sha256.getSHAStr();
        } else if (hashAlg.equals("SHA384")) {
            SHA384_512 sha384 = new SHA384_512("SHA384");
            sha384.update(inputBytes);
            outputBytes = sha384.getSHAStr();
        } else if (hashAlg.equals("SHA512")) {
            SHA384_512 sha512 = new SHA384_512("SHA512");
            sha512.update(inputBytes);
            outputBytes = sha512.getSHAStr();
        }

        return outputBytes;
    }

    public byte[] getFinal(byte[] input) {
        byte[] temp1 = {};
        byte[] temp2;

        if (symAlg.equals("DES")) {
            DES des = new DES(symKey);
            temp1 = des.encrypt(input);
        } else {
            AES aes = new AES(symKey);
            temp1 = aes.encrypt(input);
        }

        RSA rsa = new RSA();
        temp2 = rsa.encrypt(symKey, puB, "public");

        byte[] output = new byte[temp1.length + temp2.length];
        System.arraycopy(temp1, 0, output, 0, temp1.length);
        System.arraycopy(temp2, 0, output, temp1.length, temp2.length);

        return output;
    }

    public byte[] getSymKey(byte[] input) {
        RSA rsa = new RSA();
        return rsa.decrypt(input,prB,"public");
    }

    public byte[] getComboBytes(byte[] input, byte[] decryptedSymKey){
        byte[] output;
        if (symAlg.equals("DES")) {
            DES des = new DES(decryptedSymKey);
            output = des.decrypt(input);
        } else {
            AES aes = new AES(decryptedSymKey);
            output = aes.decrypt(input);
        }
        return output;

    }

    public byte[] getEncryptedSig(byte[] input){
        RSA rsa = new RSA();
        return rsa.decrypt(input,puA,"private");
    }
}

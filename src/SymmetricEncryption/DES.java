package SymmetricEncryption;

import java.lang.reflect.Array;

public class DES {

    //IP置换数组
    private static final int IP[] = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    //PC1置换数组
    private static final int PC1[] = {
            57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36, 63, 55, 47, 39,
            31, 23, 15, 7, 62, 54, 46, 38,
            30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 28, 20, 12, 4
    };

    //PC2置换数组
    private static final int PC2[] = {
            14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
    };

    //32bits向48bits扩展数组
    private static final int E[] = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

    //S盒
    private static final int S[][][] = {
            {
                    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            {
                    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            {
                    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            {
                    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            {
                    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            {
                    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            {
                    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            {
                    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
    };

    //P置换数组
    private static final int P[] = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

    //IP逆置换数组
    private static final int IPInv[] = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    private byte[][] keySub;    //子密钥


    /**
     * 构造函数
     *
     * @param key 64bits密钥
     */
    public DES(byte[] key) {
        keySub = keyGen(key);
    }

    /**
     * DES加密过程
     *
     * @param input 待加密64bits明文
     * @return 64bits密文
     */
    private byte[] encryptCore(byte[] input) {

        byte[] M0 = IPSubstitute(input);

        byte[] iterResult = iteration(M0, keySub);

        byte[] C = IPInvSubstitute(iterResult);

        return C;

    }

    /**
     * 采用PKCS7Padding填充方式
     *
     * @param input
     * @return
     */
    public byte[] encrypt(byte[] input) {
        int partLen = 8;
        int len = input.length;
        int number = (int) Math.ceil((double) len / partLen);
        int mod = len % partLen;

        byte[] output;
        byte[] tempInput;
        if (mod == 0) {
            tempInput = new byte[number * partLen + 8];
            System.arraycopy(input, 0, tempInput, 0, len);
            for (int i = 0; i < partLen; i++) {
                tempInput[len + i] = (byte) partLen;
            }
            output = new byte[number * partLen + partLen];
        } else {
            tempInput = new byte[number * partLen];
            System.arraycopy(input, 0, tempInput, 0, len);
            for (int i = 0; i < partLen - mod; i++) {
                tempInput[len + i] = (byte) (partLen - mod);
            }
            output = new byte[number * partLen];
        }

        for (int i = 0; i < (output.length / partLen); i++) {
            byte[] temp = new byte[partLen];
            System.arraycopy(tempInput, i * partLen, temp, 0, partLen);
            System.arraycopy(encryptCore(temp), 0, output, i * partLen, partLen);
        }


        return output;
    }


    /**
     * DES解密过程
     *
     * @param input 待解密64bits密文
     * @return 64bits明文
     */
    public byte[] decryptCore(byte[] input) {

        byte[] C0 = IPSubstitute(input);

        byte[][] key48 = keyInv(keySub);

        byte[] iterResult = iteration(C0, key48);

        byte[] M = IPInvSubstitute(iterResult);

        return M;
    }

    public byte[] decrypt(byte[] input) {
        int len = input.length;
        int partLen = 8;
        int number = len / partLen;


        byte[] tempOutput = new byte[len];
        byte[] output;

        for (int i = 0; i < number; i++) {
            byte[] temp = new byte[partLen];
            System.arraycopy(input, i * partLen, temp, 0, partLen);
            System.arraycopy(decryptCore(temp), 0, tempOutput, i * partLen, partLen);
        }
        if (tempOutput[len - 1] == 0x08) {
            output = new byte[len - partLen];
            System.arraycopy(tempOutput, 0, output, 0, len - partLen);
        } else {
            int x = tempOutput[len - 1];
            output = new byte[len - x];
            System.arraycopy(tempOutput, 0, output, 0, len - x);
        }
        return output;
    }

    /**
     * IP逆置换
     *
     * @param input 64bits数据
     * @return 置换后64bits数据
     */
    private byte[] IPInvSubstitute(byte[] input) {
        byte[] C = new byte[8];
        byteSubstitute(C, input, IPInv);
        return C;
    }

    /**
     * 主迭代过程，包括分成左右各32bits，再进行16轮Feistel迭代
     *
     * @param M0    输入的IP置换后的64bits数据
     * @param key48 子密钥
     * @return 64bits迭代结果
     */
    private byte[] iteration(byte[] M0, byte[][] key48) {
        byte[] L = new byte[4];
        byte[] R = new byte[4];
        byte[] iterResult = new byte[8];
        for (int i = 0; i < 4; i++) {
            L[i] = M0[i];
            R[i] = M0[i + 4];
        }

        for (int i = 0; i < 16; i++) {
            byte[] nextL = new byte[4];
            System.arraycopy(R, 0, nextL, 0, 4);
            byte[] fr = feistel(R, key48[i]);

            for (int j = 0; j < 4; j++) {
                R[j] = (byte) (L[j] ^ fr[j]);
            }

            System.arraycopy(nextL, 0, L, 0, 4);

        }
        for (int i = 0; i < 4; i++) {
            iterResult[i] = R[i];
            iterResult[i + 4] = L[i];
        }
        return iterResult;
    }

    /**
     * Feistel函数，先将32bits扩展成48bits，再与子密钥异或，再通过S盒，最后进行P置换
     *
     * @param input 输入当前轮右边32bits
     * @param key   当前轮子密钥
     * @return
     */
    private byte[] feistel(byte[] input, byte[] key) {
        byte[] expandR = expand32To48(input);
        byte[] xorResult = new byte[6];
        for (int i = 0; i < 6; i++) {
            xorResult[i] = (byte) (expandR[i] ^ key[i]);
        }

        byte[] fResult = new byte[4];

        long fResultTemp = 0;

        for (int i = 0; i < 8; i++) {
            int row = getBit(xorResult, 6 * i) << 1 | getBit(xorResult, 6 * i + 5);
            int col = (getBit(xorResult, 6 * i + 1) << 3) | (getBit(xorResult, 6 * i + 2) << 2) | (getBit(xorResult, 6 * i + 3) << 1) | (getBit(xorResult, 6 * i + 4));
            fResultTemp += (Math.pow(16, 7 - i) * S[i][row][col]);
        }

        fResult[0] = (byte) (fResultTemp >> 24 & 0xff);
        fResult[1] = (byte) (fResultTemp >> 16 & 0xff);
        fResult[2] = (byte) (fResultTemp >> 8 & 0xff);
        fResult[3] = (byte) (fResultTemp & 0xff);

        fResult = PSubstitute(fResult);


        return fResult;
    }

    /**
     * 将32bits扩展置换成48bits
     *
     * @param input 32bits输入
     * @return 48bits输出
     */
    private byte[] expand32To48(byte[] input) {
        byte[] expand = new byte[6];
        byteSubstitute(expand, input, E);
        return expand;
    }

    /**
     * 初始IP置换
     *
     * @param input 输入的64bits明文
     * @return IP置换64bits结果
     */
    private byte[] IPSubstitute(byte[] input) {

        byte[] IPText = new byte[8];
        byteSubstitute(IPText, input, IP);
        return IPText;
    }

    /**
     * P置换
     *
     * @param input 32bits输入
     * @return 32bit输出
     */
    private byte[] PSubstitute(byte[] input) {
        byte[] PText = new byte[4];
        byteSubstitute(PText, input, P);
        return PText;
    }

    /**
     * 获得输入字节数组的特定bit位
     *
     * @param input    64位字节数组
     * @param position
     * @return 该位比特值
     */
    private static byte getBit(byte[] input, int position) {
        int bitPos = position % 8;
        int len = position / 8;
        byte re;
        re = (byte) ((input[len] >>> (7 - bitPos) & 0x1));
        return re;
    }

    /**
     * 生成16轮子密钥，先将密钥压缩为56位，再通过分组移位等操作生成16组48位子密钥
     *
     * @param key 用户输入密钥
     * @return 16轮子密钥
     */
    private byte[][] keyGen(byte[] key) {
        byte[][] key48 = new byte[16][6];
        byte[] key56 = key64To56(key);

        byte[] key56Bit = new byte[56];
        byte2Bit(key56Bit, key56);
        byte[] C = new byte[28];
        byte[] D = new byte[28];

        for (int i = 0; i < 28; i++) {
            C[i] = key56Bit[i];
            D[i] = key56Bit[i + 28];
        }

        for (int i = 0; i < 16; i++) {
            if (i == 0 || i == 1 || i == 8 || i == 15) {
                C = key28ShiftLeft(C, 1);
                D = key28ShiftLeft(D, 1);
            } else {
                C = key28ShiftLeft(C, 2);
                D = key28ShiftLeft(D, 2);
            }
            for (int j = 0; j < 28; j++) {
                key56Bit[j] = C[j];
                key56Bit[j + 28] = D[j];
            }
            bit2Byte(key56, key56Bit);
            key48[i] = key56To48(key56);

        }

        return key48;
    }

    /**
     * 28bits数据循环左移函数
     *
     * @param input  28bits
     * @param offset 移动位数
     * @return
     */
    private byte[] key28ShiftLeft(byte[] input, int offset) {
        offset = offset % 28;
        for (int i = 0; i < offset; ++i) {
            byte temp;
            temp = input[0];
            for (int j = 0; j < 27; j++)
                input[j] = input[j + 1];
            input[27] = temp;
        }


        return input;
    }

    /**
     * PC1密钥压缩
     *
     * @param key 64bits
     * @return 56bits
     */
    private byte[] key64To56(byte[] key) {
        byte[] key56 = new byte[7];
        byteSubstitute(key56, key, PC1);
        return key56;
    }

    /**
     * PC2密钥压缩
     *
     * @param key 56bits
     * @return 48bits
     */
    private byte[] key56To48(byte[] key) {
        byte[] key48 = new byte[6];
        byteSubstitute(key48, key, PC2);
        return key48;
    }

    /**
     * IP、IP逆、PC1、PC2等置换主过程
     *
     * @param output 置换后的结果
     * @param input  待置换数据
     * @param subArr 置换矩阵
     */
    private void byteSubstitute(byte[] output, byte[] input, int[] subArr) {
        for (int i = 0; i < output.length; i++) {
            output[i] = (byte) ((getBit(input, subArr[i * 8] - 1)) << 7);
            output[i] += (getBit(input, subArr[i * 8 + 1] - 1)) << 6;
            output[i] += (getBit(input, subArr[i * 8 + 2] - 1)) << 5;
            output[i] += (getBit(input, subArr[i * 8 + 3] - 1)) << 4;
            output[i] += (getBit(input, subArr[i * 8 + 4] - 1)) << 3;
            output[i] += (getBit(input, subArr[i * 8 + 5] - 1)) << 2;
            output[i] += (getBit(input, subArr[i * 8 + 6] - 1)) << 1;
            output[i] += (getBit(input, subArr[i * 8 + 7] - 1));
        }
    }

    /**
     * 字节数组拆分每一位为一个字节数组元素
     *
     * @param output 输出的“位”数组
     * @param input  输入的字节数组
     */
    private static void byte2Bit(byte[] output, byte[] input) {
        for (int i = 0; i < output.length; i++) {
            output[i] = getBit(input, i);
        }
    }

    /**
     * “位”数组合成字节数组
     *
     * @param output 输出的字节数组
     * @param input  输入的“位”数组
     */
    private static void bit2Byte(byte[] output, byte[] input) {
        for (int i = 0; i < output.length; i++) {
            output[i] = (byte) (input[i * 8] << 7);
            output[i] += input[i * 8 + 1] << 6;
            output[i] += input[i * 8 + 2] << 5;
            output[i] += input[i * 8 + 3] << 4;
            output[i] += input[i * 8 + 4] << 3;
            output[i] += input[i * 8 + 5] << 2;
            output[i] += input[i * 8 + 6] << 1;
            output[i] += input[i * 8 + 7];
        }
    }

    /**
     * 解密过程中的密钥置换
     *
     * @param key48 16轮子密钥
     * @return 置换后的16轮子密钥
     */
    private byte[][] keyInv(byte[][] key48) {
        byte[] tmp = new byte[6];
        byte[][] keyOut = new byte[16][6];
        for (int i = 0; i < 8; i++) {
            System.arraycopy(key48[i], 0, keyOut[15-i], 0, 6);
            System.arraycopy(key48[15 - i], 0, keyOut[i], 0, 6);
        }
        return keyOut;
    }

    public static void printByteArray(byte[] input) {
        for (int i = 0; i < input.length; i++) {
            System.out.print(Integer.toHexString(input[i] & 0xff) + " ");
        }
        System.out.println();
    }


    public static void main(String[] args) {
        byte[] M = {
                0x01, 0x23, 0x45, 0x67,
                (byte) 0xab, (byte) 0xcd, (byte) 0xef, 0x23, 0x45, 0x67,
                (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef
        };


        byte[] key = {
                0x13, 0x34, 0x57, 0x79,
                (byte) 0x9b, (byte) 0xbc, (byte) 0xdf, (byte) 0xf1
        };
        DES des = new DES(key);


        byte[] C = des.encrypt(M);
        printByteArray(C);

        byte[] MM = des.decrypt(C);
        printByteArray(MM);



    }


}

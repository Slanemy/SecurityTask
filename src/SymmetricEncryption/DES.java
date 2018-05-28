package SymmetricEncryption;

import java.lang.reflect.Array;

public class DES {

    private final int IP[] = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    private final int PC1[] = {
            57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36, 63, 55, 47, 39,
            31, 23, 15, 7, 62, 54, 46, 38,
            30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 28, 20, 12, 4
    };

    private final int PC2[] = {
            14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
    };

    private final int E[] = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

    private final int S[][][] = {
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

    private final int P[] = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

    private final int IPInv[] = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };


    private byte[] result;

    public byte[] getResult() {
        return result;
    }

    public DES(byte[] input, byte[] key, String mode) {
        if (mode.equals("encrypt")) {
            result = encrypt(input, key);
        } else if (mode.equals("decrypt")) {
            result = decrypt(input, key);
        } else {
            System.out.println("Please re-input DES mode.");
        }
    }

    private byte[] encrypt(byte[] input, byte key[]) {

        byte[] M0 = IPSubstitute(input);

        byte[][] key48 = keyGen(key);

        byte[] iterResult = iteration(M0, key48);

        byte[] C = IPInvSubstitute(iterResult);

        return C;

    }

    private byte[] decrypt(byte[] input, byte key[]) {

        byte[] C0 = IPSubstitute(input);

        byte[][] key48 = keyGen(key);

        key48 = keyInv(key48);

        byte[] iterResult = iteration(C0, key48);

        byte[] M = IPInvSubstitute(iterResult);

        return M;
    }

    private byte[] IPInvSubstitute(byte[] input) {
        byte[] C = new byte[8];
        byteSubstitute(C, input, IPInv);
        return C;
    }

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

    private byte[] expand32To48(byte[] input) {
        byte[] expand = new byte[6];
        byteSubstitute(expand, input, E);
        return expand;
    }

    /**
     * 初始IP置换
     *
     * @param input 输入的64位明文
     * @return IP置换结果
     */
    private byte[] IPSubstitute(byte[] input) {

        byte[] IPText = new byte[8];
        byteSubstitute(IPText, input, IP);
        return IPText;
    }

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
    private byte getBit(byte[] input, int position) {
        int bitPos = position % 8;
        int len = position / 8;
        byte re;
        re = (byte) ((input[len] >>> (7 - bitPos) & 0x1));
        return re;
    }

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

    private byte[] key64To56(byte[] key) {
        byte[] key56 = new byte[7];
        byteSubstitute(key56, key, PC1);
        return key56;
    }

    private byte[] key56To48(byte[] key) {
        byte[] key48 = new byte[6];
        byteSubstitute(key48, key, PC2);
        return key48;
    }

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

    private void byte2Bit(byte[] output, byte[] input) {
        for (int i = 0; i < output.length; i++) {
            output[i] = getBit(input, i);
        }
    }

    private void bit2Byte(byte[] output, byte[] input) {
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

    private byte[][] keyInv(byte[][] key48) {
        byte[] tmp = new byte[6];
        for (int i = 0; i < 8; i++) {
            System.arraycopy(key48[i], 0, tmp, 0, 6);
            System.arraycopy(key48[15 - i], 0, key48[i], 0, 6);
            System.arraycopy(tmp, 0, key48[15 - i], 0, 6);
        }
        return key48;
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
                (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef
        };


        byte[] key = {
                0x13, 0x34, 0x57, 0x79,
                (byte) 0x9b, (byte) 0xbc, (byte) 0xdf, (byte) 0xf1
        };
        DES des = new DES(M, key, "encrypt");

        byte[] C = des.getResult();

        printByteArray(C);

        DES edes = new DES(C, key, "decrypt");

        printByteArray(edes.getResult());


    }


}

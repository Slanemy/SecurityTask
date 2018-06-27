package SymmetricEncryption;

public class AES {

    private static final int S[][] = {
            // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, // 0
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, // 1
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, // 2
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, // 3
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, // 4
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, // 5
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, // 6
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, // 7
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, // 8
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, // 9
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, // a
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, // b
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, // c
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, // d
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, // e
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}  // f
    };

    private static final int invS[][] = {
            // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, // 0
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, // 1
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, // 2
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, // 3
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, // 4
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, // 5
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, // 6
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, // 7
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, // 8
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, // 9
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, // a
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, // b
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, // c
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, // d
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, // e
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}  // f
    };

    private static final int RC[] = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    private byte[][] keySub;    //子密钥

    public AES(byte[] key) {
        keySub = keyExpansion(key);
    }


    private byte[] encryptCore(byte[] input) {
        byte[] output = {};
        byte[][] tempOutput;
        output = addRoundKey(input, 0);
        for (int i = 0; i < 9; i++) {
            output = subBytes(output, "encrypt");
            tempOutput = byte16ToByte44(output);
            tempOutput = shiftRows(tempOutput, "encrypt");
            tempOutput = mixColumns(tempOutput, "encrypt");
            output = byte44ToByte16(tempOutput);
            output = addRoundKey(output, i + 1);
        }
        output = subBytes(output, "encrypt");
        tempOutput = byte16ToByte44(output);
        tempOutput = shiftRows(tempOutput, "encrypt");
        output = byte44ToByte16(tempOutput);
        output = addRoundKey(output, 10);
        return output;
    }

    /**
     * 采用PKCS7Padding填充方式
     *
     * @param input
     * @return
     */
    public byte[] encrypt(byte[] input) {
        int partLen = 16;
        int len = input.length;
        int number = (int) Math.ceil((double) len / partLen);
        int mod = len % partLen;

        byte[] output;
        byte[] tempInput;
        if (mod == 0) {
            tempInput = new byte[number * partLen + partLen];
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

    private byte[] decryptCore(byte[] input) {
        byte[] output = {};
        byte[][] tempOutput;
        output = addRoundKey(input, 10);
        tempOutput = byte16ToByte44(output);
        for (int i = 0; i < 9; i++) {
            tempOutput = shiftRows(tempOutput, "decrypt");
            output = byte44ToByte16(tempOutput);
            output = subBytes(output, "decrypt");
            output = addRoundKey(output, 9 - i);
            tempOutput = byte16ToByte44(output);
            tempOutput = mixColumns(tempOutput, "decrypt");
        }
        tempOutput = shiftRows(tempOutput, "decrypt");
        output = byte44ToByte16(tempOutput);
        output = subBytes(output, "decrypt");
        output = addRoundKey(output, 0);

        return output;
    }

    public byte[] decrypt(byte[] input){
        int len = input.length;
        int partLen = 16;
        int number = len / partLen;


        byte[] tempOutput = new byte[len];
        byte[] output;

        for (int i = 0; i < number; i++) {
            byte[] temp = new byte[partLen];
            System.arraycopy(input, i * partLen, temp, 0, partLen);
            System.arraycopy(decryptCore(temp), 0, tempOutput, i * partLen, partLen);
        }
        if (tempOutput[len - 1] == (byte)partLen) {
            output = new byte[len - partLen];
            System.arraycopy(tempOutput, 0, output, 0, len - partLen);
        } else {
            int x = tempOutput[len - 1];
            output = new byte[len - x];
            System.arraycopy(tempOutput, 0, output, 0, len - x);
        }
        return output;
    }

    private byte[] addRoundKey(byte[] input, int round) {
        byte[] output = new byte[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i * 4 + j] = (byte) (input[i * 4 + j] ^ keySub[i + 4 * round][j]);
            }
        }
        return output;
    }

    private byte[][] mixColumns(byte[][] input, String mode) {
        byte[][] output = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            byte temp0 = input[0][i];
            byte temp1 = input[1][i];
            byte temp2 = input[2][i];
            byte temp3 = input[3][i];
            if (mode.equals("encrypt")) {
                output[0][i] = (byte) (AESMultiply(temp0, (byte) 0x02) ^ AESMultiply(temp1, (byte) 0x03) ^ temp2 ^ temp3);
                output[1][i] = (byte) (temp0 ^ AESMultiply(temp1, (byte) 0x02) ^ AESMultiply(temp2, (byte) 0x03) ^ temp3);
                output[2][i] = (byte) (temp0 ^ temp1 ^ AESMultiply(temp2, (byte) 0x02) ^ AESMultiply(temp3, (byte) 0x03));
                output[3][i] = (byte) (AESMultiply(temp0, (byte) 0x03) ^ temp1 ^ temp2 ^ AESMultiply(temp3, (byte) 0x02));
            } else {
                output[0][i] = (byte) (AESMultiply(temp0, (byte) 0x0e) ^ AESMultiply(temp1, (byte) 0x0b) ^ AESMultiply(temp2, (byte) 0x0d) ^ AESMultiply(temp3, (byte) 0x09));
                output[1][i] = (byte) (AESMultiply(temp0, (byte) 0x09) ^ AESMultiply(temp1, (byte) 0x0e) ^ AESMultiply(temp2, (byte) 0x0b) ^ AESMultiply(temp3, (byte) 0x0d));
                output[2][i] = (byte) (AESMultiply(temp0, (byte) 0x0d) ^ AESMultiply(temp1, (byte) 0x09) ^ AESMultiply(temp2, (byte) 0x0e) ^ AESMultiply(temp3, (byte) 0x0b));
                output[3][i] = (byte) (AESMultiply(temp0, (byte) 0x0b) ^ AESMultiply(temp1, (byte) 0x0d) ^ AESMultiply(temp2, (byte) 0x09) ^ AESMultiply(temp3, (byte) 0x0e));
            }
        }
        return output;
    }


    private byte AESMultiply(byte a, byte b) {
        byte[] temp = new byte[8];
        temp[0] = a;
        byte tempMultiply;
        for (int i = 1; i < 8; i++) {
            temp[i] = AESMultiple2(temp[i - 1]);
        }
        tempMultiply = (byte) ((b & 0x01) * a);
        for (int i = 1; i <= 7; i++) {
            tempMultiply ^= (((b >> i) & 0x01) * temp[i]);
        }
        return tempMultiply;
    }

    private byte AESMultiple2(byte input) {
        byte output;
        if (input >> 8 == 0) {
            output = (byte) (input << 1);
        } else {
            output = (byte) ((input << 1) ^ 0x1b);
        }
        return output;
    }


    private byte[] subBytes(byte[] input, String mode) {
        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++) {
            output[i] = byteSSubstitute(input[i], mode);
        }
        return output;
    }

    private byte[][] shiftRows(byte[][] input, String mode) {
        byte[] temp;
        byte[][] output = new byte[4][4];
        System.arraycopy(input[0], 0, output[0], 0, 4);
        for (int i = 1; i < 4; i++) {
            if (mode.equals("encrypt")) {
                temp = loopLeftShift(input[i], i);
            } else {
                temp = loopRightShift(input[i], i);
            }
            System.arraycopy(temp, 0, output[i], 0, 4);
        }

        return input;
    }

    private byte[][] byte16ToByte44(byte[] input) {
        byte[][] output = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[j][i] = input[i * 4 + j];
            }
        }
        return output;
    }

    private static byte[] byte44ToByte16(byte[][] input) {
        byte[] output = new byte[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i * 4 + j] = input[j][i];
            }
        }
        return output;
    }

    private static byte[] loopLeftShift(byte[] input, int p) {
        int i;
        byte temp;
        int N = input.length;

        for (i = 0; i < N / 2; i++) {
            temp = input[i];
            input[i] = input[N - 1 - i];
            input[N - 1 - i] = temp;
        }
        for (i = 0; i < (N - p) / 2; i++) {
            temp = input[i];
            input[i] = input[N - p - 1 - i];
            input[N - p - 1 - i] = temp;
        }
        for (i = N - p; i < N - p / 2; i++) {
            temp = input[i];
            input[i] = input[2 * N - p - 1 - i];
            input[2 * N - p - 1 - i] = temp;
        }
        return input;

    }

    public static byte[] loopRightShift(byte input[], int k) {
        k = k % input.length;
        int index = input.length - k;
        reverse(input, 0, index - 1);
        reverse(input, index, input.length - 1);
        reverse(input, 0, input.length - 1);
        return input;
    }

    public static byte[] reverse(byte input[], int s, int e) {
        while (s < e) {
            byte t = input[s];
            input[s] = input[e];
            input[e] = t;
            s++;
            e--;
        }
        return input;
    }

    private byte[][] keyExpansion(byte[] key) {
        byte[][] output = new byte[44][4];
        byte[] temp = new byte[4];
        for (int i = 0; i < 4; i++) {
            output[i][0] = key[i * 4];
            output[i][1] = key[i * 4 + 1];
            output[i][2] = key[i * 4 + 2];
            output[i][3] = key[i * 4 + 3];
        }
        for (int i = 4; i < 44; i++) {
            System.arraycopy(output[i - 1], 0, temp, 0, 4);
            if (i % 4 == 0) {
                byte tempByte;
                tempByte = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = tempByte;

                for (int j = 0; j < 4; j++) {
                    temp[j] = byteSSubstitute(temp[j], "key");
                }

                temp[0] = (byte) (temp[0] ^ RC[(i / 4) - 1] & 0xff);
            }

            byte[] tem = new byte[4];
            for (int j = 0; j < 4; j++) {
                tem[j] = (byte) (output[i - 4][j] ^ temp[j]);
            }

            System.arraycopy(tem, 0, output[i], 0, 4);
        }
        return output;
    }

    private byte byteSSubstitute(byte input, String mode) {
        int row, col;
        row = (input & 0xf0) >> 4;
        col = input & 0x0f;
        if (mode.equals("encrypt") || mode.equals("key")) {
            return (byte) S[row][col];
        } else {
            return (byte) invS[row][col];
        }
    }

    public static void printByteArray(byte[] input) {
        for (int i = 0; i < input.length; i++) {
            System.out.print(Integer.toHexString(input[i] & 0xff) + " ");
        }
        System.out.println();
    }

    public static void printByte2Array(byte[][] input) {
        for (int i = 0; i < input.length; i++) {
            for (int j = 0; j < input[i].length; j++) {
                System.out.print(Integer.toHexString(input[i][j] & 0xff) + " ");
            }
        }
        System.out.println();
    }

    public static void main(String[] args) {
        byte[] key = {0x0f, 0x15, 0x71, (byte) 0xc9, 0x47, (byte) 0xd9, (byte) 0xe8, 0x59, 0x0c, (byte) 0xb7, (byte) 0xad, (byte) 0xd6, (byte) 0xaf, 0x7f, 0x67, (byte) 0x98};
        byte[] message = {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10,
                0x01, 0x23, 0x45, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10};
        byte[] cipher = {(byte) 0xff, 0x0b, (byte) 0x84, 0x4a, 0x08, 0x53, (byte) 0xbf, 0x7c, 0x69, 0x34, (byte) 0xab, 0x43, 0x64, 0x14, (byte) 0x8f, (byte) 0xb9};
        AES test = new AES(key);
        printByteArray(test.encrypt(message));
        printByteArray(test.decrypt(test.encrypt(message)));
        System.out.println(test.decrypt(test.encrypt(message)).length);
        System.out.println(message.length);
    }
}

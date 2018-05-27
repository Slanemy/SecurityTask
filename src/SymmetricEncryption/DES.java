package SymmetricEncryption;

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


    private byte[] result;

    public DES(byte[] input, byte[] key, String mode) {
        if (mode.equals("encrypt")) {
            result = encrypt(input, key);
        } else if (mode.equals("decrypt")) {
            result = decrypt(input, key);
        } else {
            System.out.println("Please re-input.");
        }
    }

    private byte[] encrypt(byte[] input, byte key[]) {
        byte[] M0 = IP_Substitute(input);
    }

    /**
     * 初始IP置换
     *
     * @param input 输入的64位明文
     * @return IP置换结果
     */
    private byte[] IP_Substitute(byte[] input) {
        byte[] IPText = new byte[8];
        for (int i = 0; i < 8; i++) {
            IPText[i] = 0;
        }
        for (int i = 0; i < 8; i++) {
            IPText[i] += (getBit(input, IP[i * 8] - 1)) << 7;
            IPText[i] += (getBit(input, IP[i * 8 + 1] - 1)) << 6;
            IPText[i] += (getBit(input, IP[i * 8 + 2] - 1)) << 5;
            IPText[i] += (getBit(input, IP[i * 8 + 3] - 1)) << 4;
            IPText[i] += (getBit(input, IP[i * 8 + 4] - 1)) << 3;
            IPText[i] += (getBit(input, IP[i * 8 + 5] - 1)) << 2;
            IPText[i] += (getBit(input, IP[i * 8 + 6] - 1)) << 1;
            IPText[i] += (getBit(input, IP[i * 8 + 7] - 1));
        }
        return IPText;
    }

    private byte getBit(byte[] input, int position) {
        int bitPos = position % 8;
        int len = position / 8;
        byte re;
        re = (byte) ((input[len] >>> (7 - bitPos) & 0x1));
        return re;
    }

    public static void printByteArray(byte[] input) {
        for (int i = 0; i < input.length; i++) {
            System.out.print(Integer.toHexString(input[i] & 0xff) + " ");
        }
        System.out.println();
    }


    public static void main(String[] args) {
        System.out.println();
        DES des = new DES();


    }


}

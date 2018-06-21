package Hash;

import java.math.BigInteger;
import java.security.MessageDigest;


public class SHA384_512 {

    private static final long SHA384H0[] = {
            0xcbbb9d5dc1059ed8L, 0x629a292a367cd507L,
            0x9159015a3070dd17L, 0x152fecd8f70e5939L,
            0x67332667ffc00b31L, 0x8eb44a8768581511L,
            0xdb0c2e0d64f98fa7L, 0x47b5481dbefa4fa4L
    };

    //SHA256
    private static final long SHA512H0[] = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    //轮常数
    private static final long K[] = {
            0x428A2F98D728AE22L, 0x7137449123EF65CDL, 0xB5C0FBCFEC4D3B2FL,
            0xE9B5DBA58189DBBCL, 0x3956C25BF348B538L, 0x59F111F1B605D019L,
            0x923F82A4AF194F9BL, 0xAB1C5ED5DA6D8118L, 0xD807AA98A3030242L,
            0x12835B0145706FBEL, 0x243185BE4EE4B28CL, 0x550C7DC3D5FFB4E2L,
            0x72BE5D74F27B896FL, 0x80DEB1FE3B1696B1L, 0x9BDC06A725C71235L,
            0xC19BF174CF692694L, 0xE49B69C19EF14AD2L, 0xEFBE4786384F25E3L,
            0x0FC19DC68B8CD5B5L, 0x240CA1CC77AC9C65L, 0x2DE92C6F592B0275L,
            0x4A7484AA6EA6E483L, 0x5CB0A9DCBD41FBD4L, 0x76F988DA831153B5L,
            0x983E5152EE66DFABL, 0xA831C66D2DB43210L, 0xB00327C898FB213FL,
            0xBF597FC7BEEF0EE4L, 0xC6E00BF33DA88FC2L, 0xD5A79147930AA725L,
            0x06CA6351E003826FL, 0x142929670A0E6E70L, 0x27B70A8546D22FFCL,
            0x2E1B21385C26C926L, 0x4D2C6DFC5AC42AEDL, 0x53380D139D95B3DFL,
            0x650A73548BAF63DEL, 0x766A0ABB3C77B2A8L, 0x81C2C92E47EDAEE6L,
            0x92722C851482353BL, 0xA2BFE8A14CF10364L, 0xA81A664BBC423001L,
            0xC24B8B70D0F89791L, 0xC76C51A30654BE30L, 0xD192E819D6EF5218L,
            0xD69906245565A910L, 0xF40E35855771202AL, 0x106AA07032BBD1B8L,
            0x19A4C116B8D2D0C8L, 0x1E376C085141AB53L, 0x2748774CDF8EEB99L,
            0x34B0BCB5E19B48A8L, 0x391C0CB3C5C95A63L, 0x4ED8AA4AE3418ACBL,
            0x5B9CCA4F7763E373L, 0x682E6FF3D6B2B8A3L, 0x748F82EE5DEFB2FCL,
            0x78A5636F43172F60L, 0x84C87814A1F0AB72L, 0x8CC702081A6439ECL,
            0x90BEFFFA23631E28L, 0xA4506CEBDE82BDE9L, 0xBEF9A3F7B2C67915L,
            0xC67178F2E372532BL, 0xCA273ECEEA26619CL, 0xD186B8C721C0C207L,
            0xEADA7DD6CDE0EB1EL, 0xF57D4F7FEE6ED178L, 0x06F067AA72176FBAL,
            0x0A637DC5A2C898A6L, 0x113F9804BEF90DAEL, 0x1B710B35131C471BL,
            0x28DB77F523047D84L, 0x32CAAB7B40C72493L, 0x3C9EBE0A15C9BEBCL,
            0x431D67C49C100D4CL, 0x4CC5D4BECB3E42B6L, 0x597F299CFC657E2AL,
            0x5FCB6FAB3AD6FAECL, 0x6C44198C4A475817L
    };

    private static final int ROUND = 80; // 轮数

    private static final int STR_LEN = 128; // 块长度


    private int digestLen;  // 消息摘要长度

    private static final byte[] PADDING;

    static {
        PADDING = new byte[128];
        PADDING[0] = (byte) 0x80;
    }


    private long[] initState = {};// state数组的初始值

    private long[] state; // 8个链接变量

    private long[] temp; // 临时缓存

    private byte[] buffer; // 输入缓冲器

    private BigInteger byteProcessed; //已处理字节数

    private int bufferOffset;   //缓冲器偏移量


    /**
     * 逻辑右移
     *
     * @param bits 移动位数
     * @param word 待移位输入
     * @return 返回移位结果
     */
    private static long shiftR(int bits, long word) {
        return word >>> bits;
    }

    /**
     * 循环右移
     *
     * @param bits 移动位数
     * @param word 待移位输入
     * @return 返回移位结果
     */
    private static long rotR(int bits, long word) {
        return (word >>> bits) | (word << (64 - bits));
    }

    /**
     * 逻辑函数CH(x,y,z)
     *
     * @param x
     * @param y
     * @param z
     * @return
     */
    private static long ch(long x, long y, long z) {
        return (x & y) ^ ((~x) & z);
    }

    /**
     * 逻辑函数MAJ(x,y,z)
     *
     * @param x
     * @param y
     * @param z
     * @return
     */
    private static long maj(long x, long y, long z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    /**
     * 逻辑函数BSIG0
     *
     * @param word
     * @return
     */
    private static long bSig0(long word) {
        return rotR(28, word) ^ rotR(34, word) ^ rotR(39, word);
    }

    /**
     * 逻辑函数BSIG1
     *
     * @param word
     * @return
     */
    private static long bSig1(long word) {
        return rotR(14, word) ^ rotR(18, word) ^ rotR(41, word);
    }

    /**
     * 逻辑函数SSIG0
     *
     * @param word
     * @return
     */
    private static long sSig0(long word) {
        return rotR(1, word) ^ rotR(8, word) ^ shiftR(7, word);
    }

    /**
     * 逻辑函数SSIG1
     *
     * @param word
     * @return
     */
    private static long sSig1(long word) {
        return rotR(19, word) ^ rotR(61, word) ^ shiftR(6, word);
    }

    /**
     * 将long数组转为byte数组
     *
     * @param output
     * @param outOffset
     * @param input
     * @param inOffset
     * @param len
     */
    private static void encode(long[] input, int inOffset, byte[] output, int outOffset, int len) {
        len += outOffset;
        while (outOffset < len) {
            long i = input[inOffset++];
            output[outOffset++] = (byte) ((i >> 56) & 0xffL);
            output[outOffset++] = (byte) ((i >> 48) & 0xffL);
            output[outOffset++] = (byte) ((i >> 40) & 0xffL);
            output[outOffset++] = (byte) ((i >> 32) & 0xffL);
            output[outOffset++] = (byte) ((i >> 24) & 0xffL);
            output[outOffset++] = (byte) ((i >> 16) & 0xffL);
            output[outOffset++] = (byte) ((i >> 8) & 0xffL);
            output[outOffset++] = (byte) i;
        }
    }

    /**
     * 将byte数组转为long数组
     *
     * @param output
     * @param outOffset
     * @param input
     * @param inOffset
     * @param len
     */
    private static void decode(byte[] input, int inOffset, long[] output, int outOffset, int len) {
        len += outOffset;
        while (outOffset < len) {
            output[outOffset++] = ((input[inOffset++] & 0xffL) << 56) | ((input[inOffset++] & 0xffL) << 48) |
                    ((input[inOffset++] & 0xffL) << 40) | ((input[inOffset++] & 0xffL) << 32) | ((input[inOffset++] & 0xffL) << 24) |
                    ((input[inOffset++] & 0xffL) << 16) | ((input[inOffset++] & 0xffL) << 8) | (input[inOffset++] & 0xffL);
        }
    }

    private static void printByteArray(byte[] input) {
        for (int i = 0; i < input.length; i++) {
            System.out.print(Integer.toHexString(input[i] & 0xff) + " ");
        }
        System.out.println();
    }


    /**
     * 构造函数，初始化缓冲器，根据选择的SHA类型设置长度
     *
     * @param mode
     */
    public SHA384_512(String mode) {
        if (mode.equals("SHA384")) {
            digestLen = 48;
            initState = SHA384H0;
        } else if (mode.equals("SHA512")) {
            digestLen = 64;
            initState = SHA512H0;
        } else {
            System.out.println("Please re-input SHA mode.");
        }
        state = new long[8];
        temp = new long[ROUND];
        buffer = new byte[STR_LEN];
        reset();
    }

    private void reset() {
        System.arraycopy(initState, 0, state, 0, 8);
        byteProcessed = BigInteger.ZERO;
        bufferOffset = 0;
    }

    /**
     * 外部调用的入口函数
     *
     * @param input 输入的消息值
     * @return result 返回MD5结果
     */
    public byte[] getSHAStr(byte[] input) {
        byte[] digest = new byte[digestLen];

        SHAUpdate(input, 0, input.length);
        SHAFinal(digest);

        return digest;
    }

    /**
     * 转换输出
     *
     * @param digest
     */
    private void SHAFinal(byte[] digest) {
        BigInteger bitsProcessed = byteProcessed.shiftLeft(3);
        BigInteger mask = new BigInteger(Integer.toString(0x7f));
        int index = byteProcessed.and(mask).intValue();
        int padLen = (index < 112) ? (112 - index) : (240 - index);

        SHAUpdate(PADDING, 0, padLen);
        byte[] lengths = new byte[16];
        byte[] tempByte = bitsProcessed.toByteArray();
        System.arraycopy(tempByte, 0, lengths, 16 - tempByte.length, tempByte.length);

        System.arraycopy(lengths, 0, buffer, 112, 16);
        SHATransform(buffer, 0);

        encode(state, 0, digest, 0, digestLen);
        reset();
    }

    /**
     * SHA主循环
     *
     * @param input
     * @param offset
     * @param length
     */
    private void SHAUpdate(byte[] input, int offset, int length) {
        if (length == 0) {
            return;
        }
        if (length < 0 || offset < 0 || ((input.length - length) < offset)) {
            throw new ArrayIndexOutOfBoundsException();
        }
        byteProcessed = byteProcessed.add(new BigInteger(Integer.toString(length)));
        if (bufferOffset != 0) {
            int n = Math.min(length, buffer.length - bufferOffset);
            System.arraycopy(input, offset, buffer, bufferOffset, n);
            offset += n;
            bufferOffset += n;
            length -= n;
            if (bufferOffset >= STR_LEN) {
                SHATransform(buffer, 0);
                bufferOffset = 0;
            }
        }
        if (length > STR_LEN) {
            int i;
            for (i = 0; i < (length / STR_LEN); i++) {
                SHATransform(input, offset + i * STR_LEN);
            }
            bufferOffset = 0;
            offset += i * STR_LEN;
            length -= i * STR_LEN;
        }
        if (length > 0) {
            System.arraycopy(input, offset, buffer, bufferOffset, length);
            bufferOffset = length;
        }
    }

    /**
     * 64轮具体过程
     *
     * @param input
     * @param offset
     */
    private void SHATransform(byte[] input, int offset) {
        decode(input, offset, temp, 0, 16);
        for (int i = 16; i < ROUND; i++) {
            temp[i] = sSig1(temp[i - 2]) + temp[i - 7] + sSig0(temp[i - 15]) + temp[i - 16];
        }
        long a = state[0];
        long b = state[1];
        long c = state[2];
        long d = state[3];
        long e = state[4];
        long f = state[5];
        long g = state[6];
        long h = state[7];

        for (int i = 0; i < ROUND; i++) {
            long temp1 = h + bSig1(e) + ch(e, f, g) + K[i] + temp[i];
            long temp2 = bSig0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    public static void main(String[] args) throws Exception {
        String data = "sadhioasdopi j20982093is绗缝机欧萨分红我暗示法iOSad静安寺快乐 23u90218sfkljsa山东黄金开发商低级……%#*";
        byte[] test = data.getBytes();
        SHA384_512 sha384 = new SHA384_512("SHA384");
        SHA384_512 sha512 = new SHA384_512("SHA512");



        MessageDigest ssha384 = MessageDigest.getInstance("sha-384");
        MessageDigest ssha512 = MessageDigest.getInstance("sha-512");
        ssha384.update(test);
        printByteArray(sha384.getSHAStr(data.getBytes()));
        printByteArray(ssha384.digest());
        ssha512.update(test);
        printByteArray(sha512.getSHAStr(data.getBytes()));
        printByteArray(ssha512.digest());
    }
}

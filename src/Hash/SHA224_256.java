package Hash;

import java.security.MessageDigest;


public class SHA224_256 {

    private static final int SHA224H0[] = {
            0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
            0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
    };

    //SHA256
    private static final int SHA256H0[] = {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    //轮常数
    private static final int K[] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private static final int ROUND = 64; // 轮数

    private static final int STR_LEN = 64; // 块长度


    private int digestLen;  // 消息摘要长度

    private static final byte[] PADDING = {(byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0};

    private int[] initState = {};// state数组的初始值

    private int[] state; // 8个链接变量

    private int[] temp; // 临时缓存

    private byte[] buffer; // 输入缓冲器

    private long byteProcessed; //已处理字节数

    private int bufferOffset;   //缓冲器偏移量


    /**
     * 逻辑右移
     *
     * @param bits
     * @param word
     * @return
     */
    private static int shiftR(int bits, int word) {
        return word >>> bits;
    }

    /**
     * 循环右移
     *
     * @param bits
     * @param word
     * @return
     */
    private static int rotR(int bits, int word) {
        return (word >>> bits) | (word << (32 - bits));
    }

    /**
     * 逻辑函数CH(x,y,z)
     *
     * @param x
     * @param y
     * @param z
     * @return
     */
    private static int ch(int x, int y, int z) {
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
    private static int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    /**
     * 逻辑函数BSIG0
     *
     * @param word
     * @return
     */
    private static int bSig0(int word) {
        return rotR(2, word) ^ rotR(13, word) ^ rotR(22, word);
    }

    /**
     * 逻辑函数BSIG1
     *
     * @param word
     * @return
     */
    private static int bSig1(int word) {
        return rotR(6, word) ^ rotR(11, word) ^ rotR(25, word);
    }

    /**
     * 逻辑函数SSIG0
     *
     * @param word
     * @return
     */
    private static int sSig0(int word) {
        return rotR(7, word) ^ rotR(18, word) ^ shiftR(3, word);
    }

    /**
     * 逻辑函数SSIG1
     *
     * @param word
     * @return
     */
    private static int sSig1(int word) {
        return rotR(17, word) ^ rotR(19, word) ^ shiftR(10, word);
    }

    /**
     * 将int数组转为byte数组
     *
     * @param output
     * @param outOffset
     * @param input
     * @param inOffset
     * @param len
     */
    private static void encode(int[] input, int inOffset, byte[] output, int outOffset, int len) {
        len += outOffset;
        while (outOffset < len) {
            int i = input[inOffset++];
            output[outOffset++] = (byte) ((i >> 24) & 0xff);
            output[outOffset++] = (byte) ((i >> 16) & 0xff);
            output[outOffset++] = (byte) ((i >> 8) & 0xff);
            output[outOffset++] = (byte) i;
        }
    }

    /**
     * 将byte数组转为int数组
     *
     * @param output
     * @param outOffset
     * @param input
     * @param inOffset
     * @param len
     */
    private static void decode(byte[] input, int inOffset, int[] output, int outOffset, int len) {
        len += outOffset;
        while (outOffset < len) {
            output[outOffset++] = ((input[inOffset++] & 0xff) << 24) | ((input[inOffset++] & 0xff) << 16) |
                    ((input[inOffset++] & 0xff) << 8) | (input[inOffset++] & 0xff);
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
    private SHA224_256(String mode) {
        if(mode.equals("SHA224")){
            digestLen = 28;
            initState = SHA224H0;
        }else if (mode.equals("SHA256")){
            digestLen = 32;
            initState = SHA256H0;
        }else{
            System.out.println("Please re-input SHA mode.");
        }
        state = new int[8];
        temp = new int[ROUND];
        buffer = new byte[STR_LEN];
        reset();
    }

    private void reset() {
        System.arraycopy(initState, 0, state, 0, 8);
        byteProcessed = 0;
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
        long bitsProcessed = byteProcessed << 3;
        int index = (int) byteProcessed & 0x3f;
        int padLen = (index < 56) ? (56 - index) : (120 - index);

        SHAUpdate(PADDING, 0, padLen);
        int[] lengths = {(int) (bitsProcessed >>> 32), (int) bitsProcessed};
        encode(lengths, 0, buffer, 56, 8);
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
        if (byteProcessed < 0) {
            reset();
        }
        byteProcessed += length;
        if (bufferOffset != 0) {
            int n = Math.min(length, buffer.length - bufferOffset);
            System.arraycopy(input, offset, buffer, bufferOffset, n);
            offset += n;
            length -= n;
            bufferOffset += n;
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
            length -= i * STR_LEN;
            offset += i * STR_LEN;
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
        int a = state[0];
        int b = state[1];
        int c = state[2];
        int d = state[3];
        int e = state[4];
        int f = state[5];
        int g = state[6];
        int h = state[7];
        for (int i = 0; i < ROUND; i++) {
            int temp1 = h + bSig1(e) + ch(e, f, g) + K[i] + temp[i];
            int temp2 = bSig0(a) + maj(a, b, c);
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
        SHA224_256 sha224 = new SHA224_256("SHA224");
        SHA224_256 sha256 = new SHA224_256("SHA256");
        printByteArray(sha224.getSHAStr(data.getBytes()));
        printByteArray(sha256.getSHAStr(data.getBytes()));

        //MessageDigest ssha224 = MessageDigest.getInstance("sha-224");
        MessageDigest ssha256 = MessageDigest.getInstance("sha-256");
        ssha256.update(test);
        printByteArray(ssha256.digest());
    }
}

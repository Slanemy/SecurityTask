package Hash;

public class MD5 {
    //四个32位变量初始值
    private final long A = 0x67452301L;
    private final long B = 0xefcdab89L;
    private final long C = 0x98badcfeL;
    private final long D = 0x10325476L;

    private byte[] buffer = new byte[64]; // 输入缓冲器，即512位一组

    private long[] strLength = new long[2]; //输入字符串长度，64位

    //每一轮ti
    private final int T[] = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

    //每一轮s
    static final int S11 = 7;
    static final int S12 = 12;
    static final int S13 = 17;
    static final int S14 = 22;

    static final int S21 = 5;
    static final int S22 = 9;
    static final int S23 = 14;
    static final int S24 = 20;

    static final int S31 = 4;
    static final int S32 = 11;
    static final int S33 = 16;
    static final int S34 = 23;

    static final int S41 = 6;
    static final int S42 = 10;
    static final int S43 = 15;
    static final int S44 = 21;

    static final byte[] PADDING = {-128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0};

    public String digestHexStr; //MD5的16进制ASCII表示

    private byte[] digest = new byte[16];    //MD5二进制表示，128bit

    /**
     * 每次操作的四个非线性函数
     *
     * @param x
     * @param y
     * @param z
     */
    private long F(long x, long y, long z) {
        return (x & y) | ((~x) & z);
    }

    private long G(long x, long y, long z) {
        return (x & z) | (y & (~z));
    }

    private long H(long x, long y, long z) {
        return x ^ y ^ z;
    }

    private long I(long x, long y, long z) {
        return y ^ (x | (~z));
    }

    /**
     * 四轮每次的操作函数
     */
    private long FF(long a, long b, long c, long d, long m, long s, long t) {
        a += F(b, c, d) + m + t;
        a = ((int) a << s) | ((int) a >>> (32 - s));
        a += b;
        return a;
    }

    private long GG(long a, long b, long c, long d, long m, long s, long t) {
        a += G(b, c, d) + m + t;
        a = ((int) a << s) | ((int) a >>> (32 - s));
        a += b;
        return a;
    }

    private long HH(long a, long b, long c, long d, long m, long s, long t) {
        a += H(b, c, d) + m + t;
        a = ((int) a << s) | ((int) a >>> (32 - s));
        a += b;
        return a;
    }

    private long II(long a, long b, long c, long d, long m, long s, long t) {
        a += I(b, c, d) + m + t;
        a = ((int) a << s) | ((int) a >>> (32 - s));
        a += b;
        return a;
    }

    /**
     * 外部调用的入口函数
     *
     * @param inputBytes 输入的消息值
     * @return result 返回MD5结果
     */
    public String getMD5Str(String inputString) {
        md5Init();
        md5Update(inputString.getBytes(), inputString.length());
        md5Final();
        digestHexStr = "";
        for (int i = 0; i < 16; i++) {
            digestHexStr += byteHex(digest[i]);
        }
        return digestHexStr;
    }

    /**
     * 构造函数
     */
    public MD5() {
        md5Init();

        return;
    }

    /**
     * MD5初始化
     */
    private void md5Init() {
        strLength[0] = 0L;
        strLength[1] = 0L;

        return;
    }

    /**
     * MD5主循环过程
     *
     * @param inputByte 输入的字节串
     * @param inputLen  字节长度
     */
    private void md5Update(byte[] inputByte, int inputLen) {
        int i, index, partLen;
        byte[] block = new byte[64];
        index = (int) (strLength[0] >>> 3) & 0x3F;  //mod 64
        if ((strLength[0] += (inputLen << 3)) < (inputLen << 3))
            strLength[1]++;
        strLength[1] += (inputLen >>> 29);
        partLen = 64 - index;
        if (inputLen >= partLen) {
            System.arraycopy(inputByte, 0, buffer, index, partLen);
            md5Transform(buffer);
            for (i = partLen; i + 63 < inputLen; i += 64) {
                System.arraycopy(inputByte, i, block, 0, 64);
                md5Transform(block);
            }
            index = 0;
        } else
            i = 0;
        System.arraycopy(inputByte, i, buffer, index, inputLen - i);
    }


    /**
     * 转换输出结果
     */
    private void md5Final() {
        byte[] bits = new byte[8];
        int index, padLen;

        // /* Save number of bits */
        Encode(bits, strLength, 8);

        // /* Pad out to 56 mod 64.
        index = (int) (strLength[0] >>> 3) & 0x3f;
        padLen = (index < 56) ? (56 - index) : (120 - index);
        md5Update(PADDING, padLen);

        // /* Append length (before padding) */
        md5Update(bits, 8);

        // /* Store state in digest */
        Encode(digest, state, 16);

    }

    public static void main(String[] args) {
        MD5 md = new MD5();
        String test = new String("abcde");
        System.out.println(Integer.toHexString(md.T[20]));
        System.out.println(100 >> 2);
    }


}

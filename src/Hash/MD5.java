package Hash;

import java.security.MessageDigest;

public class MD5 {
    //四个32位变量初始值
    private long A = 0x67452301L;
    private long B = 0xefcdab89L;
    private long C = 0x98badcfeL;
    private long D = 0x10325476L;

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
     * @param inputString 输入的消息值
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
     * 将byte类型的数转换为十六进制的ASCII码
     *
     * @param ib 输入的byte字符
     * @return 一个字符
     */
    public static String byteHex(byte ib) {
        char[] Digit = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
                'B', 'C', 'D', 'E', 'F'};
        char[] ob = new char[2];
        ob[0] = Digit[(ib >>> 4) & 0X0F];
        ob[1] = Digit[ib & 0X0F];
        String s = new String(ob);
        return s;
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
        byte[] group = new byte[64];
        index = (int) (strLength[0] >>> 3) & 0x3F;  //mod 64
        if ((strLength[0] += (inputLen << 3)) < (inputLen << 3))
            strLength[1]++;
        strLength[1] += (inputLen >>> 29);
        partLen = 64 - index;
        if (inputLen >= partLen) {
            System.arraycopy(inputByte, 0, buffer, index, partLen);
            md5Transform(buffer);
            for (i = partLen; i + 63 < inputLen; i += 64) {
                System.arraycopy(inputByte, i, group, 0, 64);
                md5Transform(group);
            }
            index = 0;
        } else
            i = 0;
        System.arraycopy(inputByte, i, buffer, index, inputLen - i);
    }

    /**
     * 四轮变换具体流程
     *
     * @param group 分组的原始字节
     */

    private void md5Transform(byte group[]) {
        long a = A, b = B, c = C, d = D;
        long[] x = new long[16];

        Decode(x, group, 64);

        //第一轮
        a = FF(a, b, c, d, x[0], S11, T[0]);
        d = FF(d, a, b, c, x[1], S12, T[1]);
        c = FF(c, d, a, b, x[2], S13, T[2]);
        b = FF(b, c, d, a, x[3], S14, T[3]);
        a = FF(a, b, c, d, x[4], S11, T[4]);
        d = FF(d, a, b, c, x[5], S12, T[5]);
        c = FF(c, d, a, b, x[6], S13, T[6]);
        b = FF(b, c, d, a, x[7], S14, T[7]);
        a = FF(a, b, c, d, x[8], S11, T[8]);
        d = FF(d, a, b, c, x[9], S12, T[9]);
        c = FF(c, d, a, b, x[10], S13, T[10]);
        b = FF(b, c, d, a, x[11], S14, T[11]);
        a = FF(a, b, c, d, x[12], S11, T[12]);
        d = FF(d, a, b, c, x[13], S12, T[13]);
        c = FF(c, d, a, b, x[14], S13, T[14]);
        b = FF(b, c, d, a, x[15], S14, T[15]);

        //第二轮
        a = GG(a, b, c, d, x[1], S21, T[16]);
        d = GG(d, a, b, c, x[6], S22, T[17]);
        c = GG(c, d, a, b, x[11], S23, T[18]);
        b = GG(b, c, d, a, x[0], S24, T[19]);
        a = GG(a, b, c, d, x[5], S21, T[20]);
        d = GG(d, a, b, c, x[10], S22, T[21]);
        c = GG(c, d, a, b, x[15], S23, T[22]);
        b = GG(b, c, d, a, x[4], S24, T[23]);
        a = GG(a, b, c, d, x[9], S21, T[24]);
        d = GG(d, a, b, c, x[14], S22, T[25]);
        c = GG(c, d, a, b, x[3], S23, T[26]);
        b = GG(b, c, d, a, x[8], S24, T[27]);
        a = GG(a, b, c, d, x[13], S21, T[28]);
        d = GG(d, a, b, c, x[2], S22, T[29]);
        c = GG(c, d, a, b, x[7], S23, T[30]);
        b = GG(b, c, d, a, x[12], S24, T[31]);

        //第三轮
        a = HH(a, b, c, d, x[5], S31, T[32]);
        d = HH(d, a, b, c, x[8], S32, T[33]);
        c = HH(c, d, a, b, x[11], S33, T[34]);
        b = HH(b, c, d, a, x[14], S34, T[35]);
        a = HH(a, b, c, d, x[1], S31, T[36]);
        d = HH(d, a, b, c, x[4], S32, T[37]);
        c = HH(c, d, a, b, x[7], S33, T[38]);
        b = HH(b, c, d, a, x[10], S34, T[39]);
        a = HH(a, b, c, d, x[13], S31, T[40]);
        d = HH(d, a, b, c, x[0], S32, T[41]);
        c = HH(c, d, a, b, x[3], S33, T[42]);
        b = HH(b, c, d, a, x[6], S34, T[43]);
        a = HH(a, b, c, d, x[9], S31, T[44]);
        d = HH(d, a, b, c, x[12], S32, T[45]);
        c = HH(c, d, a, b, x[15], S33, T[46]);
        b = HH(b, c, d, a, x[2], S34, T[47]);

        //第四轮
        a = II(a, b, c, d, x[0], S41, T[48]);
        d = II(d, a, b, c, x[7], S42, T[49]);
        c = II(c, d, a, b, x[14], S43, T[50]);
        b = II(b, c, d, a, x[5], S44, T[51]);
        a = II(a, b, c, d, x[12], S41, T[52]);
        d = II(d, a, b, c, x[3], S42, T[53]);
        c = II(c, d, a, b, x[10], S43, T[54]);
        b = II(b, c, d, a, x[1], S44, T[55]);
        a = II(a, b, c, d, x[8], S41, T[56]);
        d = II(d, a, b, c, x[15], S42, T[57]);
        c = II(c, d, a, b, x[6], S43, T[58]);
        b = II(b, c, d, a, x[13], S44, T[59]);
        a = II(a, b, c, d, x[4], S41, T[60]);
        d = II(d, a, b, c, x[11], S42, T[61]);
        c = II(c, d, a, b, x[2], S43, T[62]);
        b = II(b, c, d, a, x[9], S44, T[63]);

        A += a;
        B += b;
        C += c;
        D += d;
    }

    /**
     * 将byte数组合成long数组
     *
     * @param output
     * @param input
     * @param len
     */
    private void Decode(long[] output, byte[] input, int len) {
        int i, j;
        for (i = 0, j = 0; j < len; i++, j += 4) {
            output[i] = b2iu(input[j]) | (b2iu(input[j + 1]) << 8)
                    | (b2iu(input[j + 2]) << 16) | (b2iu(input[j + 3]) << 24);
        }
        return;
    }

    /**
     * 将带符号数转换成不考虑符号的long
     *
     * @param b
     * @return
     */

    public static long b2iu(byte b) {

        return b < 0 ? b & 0x7F + 128 : b;
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

        long[] state = new long[4];
        state[0] = A;
        state[1] = B;
        state[2] = C;
        state[3] = D;
        // /* Store state in digest */
        Encode(digest, state, 16);

    }

    /**
     * 将long数组拆分为byte数组
     *
     * @param output
     * @param input
     * @param len
     */

    private void Encode(byte[] output, long[] input, int len) {
        int i, j;

        for (i = 0, j = 0; j < len; i++, j += 4) {
            output[j] = (byte) (input[i] & 0xffL);
            output[j + 1] = (byte) ((input[i] >>> 8) & 0xffL);
            output[j + 2] = (byte) ((input[i] >>> 16) & 0xffL);
            output[j + 3] = (byte) ((input[i] >>> 24) & 0xffL);
        }
    }


    public static String MD5(String key) {
        char hexDigits[] = {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
        };
        try {
            byte[] btInput = key.getBytes();
            // 获得MD5摘要算法的 MessageDigest 对象
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            // 使用指定的字节更新摘要
            mdInst.update(btInput);
            // 获得密文
            byte[] md = mdInst.digest();
            // 把密文转换成十六进制的字符串形式
            int j = md.length;
            char str[] = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
        String data = "12";
        MD5 md5 = new MD5();
        System.out.println(md5.getMD5Str(data));
        String MD5_String;
        MD5_String = MD5(data);
        System.out.println(MD5_String);

    }


}

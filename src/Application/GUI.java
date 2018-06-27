package Application;


import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.Date;


public class GUI {
    //GUI各种组件的显示程序
    private static final int DEFAULT_WIDTH = 1200;
    private static final int DEFAULT_HEIGHT = 850;
    private static final int DEFAULT_POSITION_X = 0;
    private static final int DEFAULT_POSITION_Y = 0;
    private static final String ICON = "assets/icon.jpg";
    private static final String FLOW = "assets/flow.jpg";
    private static final int OFFSET_Y = 40;
    private static final int OFFSET_X = 90;
    private static final int LINE_Y = 36;
    private static final int LINE_X = 120;
    public JFrame frame;

    private String symAlg = "DES";
    private String symKeyType = "bySeed";
    private String seed = "";
    private String hashAlg = "MD5";
    private String RSABitLength = "1024";

    private String plainText;
    private String cipherText;
    private byte[] plainBytes;
    private byte[] cipherBytes;
    private byte[] hashBytes;
    private byte[] sigBytes;
    private byte[] finalBytes;

    final BASE64Encoder base64Encoder = new BASE64Encoder();
    final BASE64Decoder base64Decoder = new BASE64Decoder();

    private Date day = new Date();
    SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");


    private static final Font YAHEI14 = new Font("微软雅黑", Font.PLAIN, 14);

    Process mainProcess;


    public GUI() {
        mainProcess = new Process();
        initFrame();
    }

    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                GUI gui = new GUI();
                gui.frame.setVisible(true);
            }
        });
    }

    private static String bytes2String(byte[] input) {
        String out = "";
        for (int i = 0; i < input.length; i++) {
            out += Integer.toHexString(input[i] & 0xff);
        }
        return out;
    }

    private void initFrame() {

        frame = new JFrame();
        frame.setTitle("消息加密算法系统");
        frame.setBounds(DEFAULT_POSITION_X, DEFAULT_POSITION_Y, DEFAULT_WIDTH, DEFAULT_HEIGHT);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setResizable(false);
        Container contentPane = frame.getContentPane();
        contentPane.setLayout(null);

        //设置程序icon
        Image img = new ImageIcon(ICON).getImage();
        frame.setIconImage(img);

        /**
         * 选择参数面板
         */
        JPanel setupPanel = new JPanel();
        setupPanel.setBounds(0, 0, 400, 280);
        Border setBorder = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "选择参数");
        setupPanel.setBorder(setBorder);
        contentPane.add(setupPanel);
        setupPanel.setLayout(null);

        JLabel lblSymmetric = new JLabel("对称加密算法：");
        lblSymmetric.setFont(YAHEI14);
        lblSymmetric.setBounds(10, LINE_Y, 150, 23);
        setupPanel.add(lblSymmetric);

        final JRadioButton jrbDES = new JRadioButton("DES", true);
        jrbDES.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbDES.setBounds(LINE_X, LINE_Y, 80, 23);
        final JRadioButton jrbAES = new JRadioButton("AES", false);
        jrbAES.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbAES.setBounds(LINE_X + OFFSET_X, LINE_Y, 100, 23);
        final ButtonGroup symmetricGroup = new ButtonGroup();
        symmetricGroup.add(jrbDES);
        symmetricGroup.add(jrbAES);
        setupPanel.add(jrbAES);
        setupPanel.add(jrbDES);

        jrbDES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                symAlg = "DES";
            }
        });

        jrbAES.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                symAlg = "AES";
            }
        });

        JLabel lblSeed = new JLabel("选择对称密钥：");
        lblSeed.setFont(YAHEI14);
        lblSeed.setBounds(10, LINE_Y + OFFSET_Y, 150, 23);
        setupPanel.add(lblSeed);

        final JComboBox<String> jcbSymKey = new JComboBox<>();
        jcbSymKey.addItem("种子生成");
        jcbSymKey.addItem("随机生成");
        jcbSymKey.setBounds(LINE_X, LINE_Y + OFFSET_Y, 150, 23);
        setupPanel.add(jcbSymKey);

        JLabel lblSymKey = new JLabel("请输入种子数（整数）");
        lblSymKey.setFont(new Font("微软雅黑", Font.PLAIN, 10));
        lblSymKey.setBounds(LINE_X + OFFSET_X + 75, LINE_Y + 18, 150, 23);
        setupPanel.add(lblSymKey);
        final JTextField jtfSymKey = new JTextField();
        jtfSymKey.setBounds(LINE_X + OFFSET_X + 75, LINE_Y + OFFSET_Y, 100, 23);
        setupPanel.add(jtfSymKey);
        jtfSymKey.setEnabled(true);
        jcbSymKey.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (jcbSymKey.getSelectedIndex() == 0) {
                    symKeyType = "bySeed";
                } else {
                    symKeyType = "byRandom";
                }
                jtfSymKey.setEnabled(jcbSymKey.getSelectedIndex() == 0);
            }
        });


        JLabel lblHash = new JLabel("HASH算法：");
        lblHash.setFont(YAHEI14);
        lblHash.setBounds(25, LINE_Y + OFFSET_Y * 2, 150, 23);
        setupPanel.add(lblHash);

        final JRadioButton jrbMD5 = new JRadioButton("MD5", true);
        jrbMD5.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbMD5.setBounds(LINE_X, LINE_Y + OFFSET_Y * 2, 90, 23);
        final JRadioButton jrbSHA224 = new JRadioButton("SHA-224", false);
        jrbSHA224.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbSHA224.setBounds(LINE_X + OFFSET_X, LINE_Y + OFFSET_Y * 2, 90, 23);
        final JRadioButton jrbSHA256 = new JRadioButton("SHA-256", false);
        jrbSHA256.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbSHA256.setBounds(LINE_X, LINE_Y + OFFSET_Y * 3, 90, 23);
        final JRadioButton jrbSHA384 = new JRadioButton("SHA-384", false);
        jrbSHA384.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbSHA384.setBounds(LINE_X + OFFSET_X, LINE_Y + OFFSET_Y * 3, 90, 23);
        final JRadioButton jrbSHA512 = new JRadioButton("SHA-512", false);
        jrbSHA512.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbSHA512.setBounds(LINE_X + OFFSET_X * 2, LINE_Y + OFFSET_Y * 3, 90, 23);

        ButtonGroup hashGroup = new ButtonGroup();
        hashGroup.add(jrbMD5);
        hashGroup.add(jrbSHA224);
        hashGroup.add(jrbSHA256);
        hashGroup.add(jrbSHA512);
        hashGroup.add(jrbSHA384);
        setupPanel.add(jrbMD5);
        setupPanel.add(jrbSHA224);
        setupPanel.add(jrbSHA256);
        setupPanel.add(jrbSHA384);
        setupPanel.add(jrbSHA512);

        jrbMD5.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "MD5";
            }
        });

        jrbSHA224.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "SHA224";
            }
        });

        jrbSHA256.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "SHA256";
            }
        });

        jrbSHA384.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "SHA384";
            }
        });

        jrbSHA512.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hashAlg = "SHA512";
            }
        });

        JLabel lblRSA = new JLabel("RSA位数：");
        lblRSA.setFont(YAHEI14);
        lblRSA.setBounds(39, LINE_Y + OFFSET_Y * 4, 150, 23);
        setupPanel.add(lblRSA);

        final JTextField jtfRSA = new JTextField("1024", 5);
        jtfRSA.setBounds(LINE_X, LINE_Y + OFFSET_Y * 4, 50, 23);
        setupPanel.add(jtfRSA);

        final JButton attrConfirm = new JButton("确定");
        attrConfirm.setBounds(120, LINE_Y + OFFSET_Y * 5, 70, 23);
        setupPanel.add(attrConfirm);


        final JButton attrReset = new JButton("重置");
        attrReset.setBounds(220, LINE_Y + OFFSET_Y * 5, 70, 23);
        setupPanel.add(attrReset);
        attrReset.setEnabled(false);

        /**
         * 传输消息面板
         */
        final JPanel plainPanel = new JPanel();
        plainPanel.setBounds(0, 280, 400, 350);
        Border setMBorder = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "传输消息");
        plainPanel.setBorder(setMBorder);
        contentPane.add(plainPanel);
        plainPanel.setLayout(null);

        JScrollPane jspPlain = new JScrollPane();
        jspPlain.setBounds(10, LINE_Y, 380, 260);
        plainPanel.add(jspPlain);
        final JTextArea jtaPlain = new JTextArea();
        jtaPlain.setBounds(10, LINE_Y, 380, 260);
        jspPlain.setViewportView(jtaPlain);
        jtaPlain.setLineWrap(true);
        //设置成只读
        jtaPlain.setEnabled(false);


        final JButton jbEncrypt = new JButton("加密");
        jbEncrypt.setBounds(150, LINE_Y + OFFSET_Y * 2 + 195, 89, 23);
        plainPanel.add(jbEncrypt);

        jbEncrypt.setEnabled(false);

        /**
         * 验证消息面板
         */
        final JPanel cipherPanel = new JPanel();
        cipherPanel.setBounds(0, 280, 400, 350);
        Border setTBorder = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "验证消息");
        cipherPanel.setBorder(setTBorder);
        contentPane.add(cipherPanel);
        cipherPanel.setVisible(false);
        cipherPanel.setLayout(null);

        JScrollPane jspCipher = new JScrollPane();
        jspCipher.setBounds(10, LINE_Y, 380, 260);
        cipherPanel.add(jspCipher);
        final JTextArea jtaCipher = new JTextArea();
        jtaCipher.setBounds(10, LINE_Y, 380, 260);
        jspCipher.setViewportView(jtaCipher);
        jtaCipher.setLineWrap(true);


        final JButton jbDecrypt = new JButton("验证");
        jbDecrypt.setBounds(100, LINE_Y + OFFSET_Y * 2 + 195, 89, 23);
        cipherPanel.add(jbDecrypt);

        final JButton jbDReset = new JButton("重置");
        jbDReset.setBounds(220, LINE_Y + OFFSET_Y * 2 + 195, 89, 23);
        cipherPanel.add(jbDReset);

        jbDecrypt.setEnabled(true);

        /**
         * 使用说明面板
         */
        JPanel instructionPanel = new JPanel();
        instructionPanel.setBounds(0, 630, 400, 170);
        Border setIBorder = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "使用说明");
        instructionPanel.setBorder(setIBorder);
        contentPane.add(instructionPanel);
        instructionPanel.setLayout(null);

        JScrollPane jspIns = new JScrollPane();
        jspIns.setBounds(10, 20, 380, 140);
        instructionPanel.add(jspIns);
        final JTextArea jtaIns = new JTextArea();
        jtaIns.setFont(YAHEI14);
        jtaIns.setBounds(10, 20, 380, 140);
        jspIns.setViewportView(jtaIns);
        jtaIns.setLineWrap(true);
        jtaIns.setText("1. 在选择参数面板中选择相关参数后按确定，可以在发送方和接收方的日志窗口查看相关信息，其中种子数必须为一个大于0的整数，RSA位数必须为1024到2048之间的整数；\n" +
                "2. 在传输消息面板输入待加密的消息，点击加密按钮即可在发送方日志中看到相关信息;\n" +
                "3. 复制接收方日志中接收到的消息到验证消息面板中，点击验证即可在接收方日志中查看验证结果；\n4. 选择参数面板中的重置按钮可以将系统全部还原，此时相当于A、B断开连接，需要重新选择参数建立" +
                "新的连接；验证消息面板中的重置按钮可在当前状态重新发送消息，此时相当于A、B已建立连接，可以一直发消息。");

        /**
         * 发送方面板
         */
        JPanel senderA = new JPanel();
        senderA.setBounds(401, 0, 790, 400);
        Border setABorder = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "发送方日志");
        senderA.setBorder(setABorder);
        contentPane.add(senderA);
        senderA.setLayout(null);

        JScrollPane jspA = new JScrollPane();
        jspA.setBounds(10, LINE_Y, 770, 340);
        senderA.add(jspA);
        final JTextArea jtaA = new JTextArea();
        jtaA.setFont(YAHEI14);
        jtaA.setBounds(10, LINE_Y, 770, 340);
        jspA.setViewportView(jtaA);
        jtaA.setLineWrap(true);


        /**
         * 接收方面板
         */
        JPanel senderB = new JPanel();
        senderB.setBounds(401, 400, 790, 400);
        Border setBBorder = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "接收方日志");
        senderB.setBorder(setBBorder);
        contentPane.add(senderB);
        senderB.setLayout(null);

        JScrollPane jspB = new JScrollPane();
        jspB.setBounds(10, LINE_Y, 770, 340);
        senderB.add(jspB);
        final JTextArea jtaB = new JTextArea();
        jtaB.setFont(YAHEI14);
        jtaB.setBounds(10, LINE_Y, 770, 340);
        jspB.setViewportView(jtaB);
        jtaB.setLineWrap(true);


        /**
         * 按钮逻辑
         */
        attrConfirm.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                String SEED = jcbSymKey.getSelectedIndex() == 0 ? jtfSymKey.getText().trim() : "1";
                String RSABITLENTH = jtfRSA.getText().trim();
                if (!SEED.matches("[1-9]+")) {
                    JOptionPane.showMessageDialog(frame, "种子数必须是一个大于0的整数",
                            "错误", JOptionPane.ERROR_MESSAGE);

                } else if (RSABITLENTH.matches("\\d+")) {
                    if (Integer.valueOf(RSABITLENTH) < 1024 || Integer.valueOf(RSABITLENTH) > 2048) {
                        JOptionPane.showMessageDialog(frame, "RSA位数必须在1024到2048之间",
                                "错误", JOptionPane.ERROR_MESSAGE);
                    } else {
                        attrReset.setEnabled(true);
                        attrConfirm.setEnabled(false);
                        jrbAES.setEnabled(false);
                        jrbDES.setEnabled(false);
                        jrbMD5.setEnabled(false);
                        jrbSHA224.setEnabled(false);
                        jrbSHA256.setEnabled(false);
                        jrbSHA384.setEnabled(false);
                        jrbSHA512.setEnabled(false);
                        jcbSymKey.setEnabled(false);
                        jtfRSA.setEnabled(false);
                        jtfSymKey.setEnabled(false);


                        jbEncrypt.setEnabled(true);

                        plainPanel.setVisible(true);
                        cipherPanel.setVisible(false);

                        if (!jtaPlain.isEnabled()) {
                            jtaPlain.setEnabled(true);
                        }

                        if (symKeyType == "bySeed") {
                            seed = jtfSymKey.getText().trim();
                        }

                        RSABitLength = jtfRSA.getText().trim();

                        /**
                         * 生成相应参数
                         */
                        mainProcess.initialize(symAlg, symKeyType, seed, hashAlg, RSABitLength);
                        mainProcess.generateKeys();

                        /**
                         * 显示在各自的文本域中
                         */
                        jtaA.append(mainProcess.getInitInfo("A"));
                        jtaB.append(mainProcess.getInitInfo("B"));
                    }
                } else {
                    JOptionPane.showMessageDialog(frame, "RSA位数必须是一个整数",
                            "错误", JOptionPane.ERROR_MESSAGE);
                }

            }
        });

        attrReset.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                attrConfirm.setEnabled(true);
                attrReset.setEnabled(false);
                jrbAES.setEnabled(true);
                jrbDES.setEnabled(true);
                jrbMD5.setEnabled(true);
                jrbSHA224.setEnabled(true);
                jrbSHA256.setEnabled(true);
                jrbSHA384.setEnabled(true);
                jrbSHA512.setEnabled(true);
                jcbSymKey.setEnabled(true);
                jtfRSA.setEnabled(true);
                jtfSymKey.setEnabled(true);

                jbEncrypt.setEnabled(false);
                if (jtaPlain.isEnabled()) {
                    jtaPlain.setEnabled(false);
                }

                if (jcbSymKey.getSelectedIndex() == 1) {
                    jtfSymKey.setEnabled(false);
                }

                jtaA.append("\n---------------------------------------------------" + df.format(day) + "---------------------------------------------------\n");
                jtaA.append("------------------------------------------------------------重置------------------------------------------------------------\n");
                jtaB.append("\n---------------------------------------------------" + df.format(day) + "---------------------------------------------------\n");
                jtaB.append("------------------------------------------------------------重置------------------------------------------------------------\n");

                plainPanel.setVisible(true);
                cipherPanel.setVisible(false);

                jtaPlain.setText("");
                jtaCipher.setText("");

            }
        });

        jbEncrypt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                plainPanel.setVisible(false);
                cipherPanel.setVisible(true);
                plainText = jtaPlain.getText();
                plainBytes = plainText.getBytes();

                jtaA.append("\n---------------------------------------------------" + df.format(day) + "---------------------------------------------------\n");
                jtaA.append("----------------------------------------------------------发送消息----------------------------------------------------------\n");
                jtaA.append("消息内容：" + plainText + "\n");
                hashBytes = mainProcess.getHash(plainBytes);
                jtaA.append(hashAlg + "：" + bytes2String(hashBytes) + "\n");
                sigBytes = mainProcess.getSignature(hashBytes);
                jtaA.append("数字签名：" + bytes2String(sigBytes) + "\n");

                byte[] comboBytes = new byte[plainBytes.length + sigBytes.length];
                System.arraycopy(plainBytes, 0, comboBytes, 0, plainBytes.length);
                System.arraycopy(sigBytes, 0, comboBytes, plainBytes.length, sigBytes.length);


                finalBytes = mainProcess.getFinal(comboBytes);
                jtaA.append("发送消息：" + base64Encoder.encode(finalBytes) + "\n");
                jtaA.append("-----------------------------------------------------------------------------------------------------------------------------\n");

                jtaB.append("\n---------------------------------------------------" + df.format(day) + "---------------------------------------------------\n");
                jtaB.append("----------------------------------------------------------接收消息----------------------------------------------------------\n");
                jtaB.append("接收消息：" + base64Encoder.encode(finalBytes) + "\n");
                jtaB.append("-----------------------------------------------------------------------------------------------------------------------------\n");


            }
        });

        jbDecrypt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cipherText = jtaCipher.getText();
                try {
                    cipherBytes = base64Decoder.decodeBuffer(cipherText);
                } catch (Exception err) {
                    System.out.println(err);
                }
                int decryptedSymKeyLen = Integer.valueOf(RSABitLength) / 8;
                int hashLen = 0;
                int encryptedSigLen = 0;
                if (hashAlg.equals("MD5")) {
                    hashLen = 16;
                } else if (hashAlg.equals("SHA224")) {
                    hashLen = 28;
                } else if (hashAlg.equals("SHA256")) {
                    hashLen = 32;
                } else if (hashAlg.equals("SHA384")) {
                    hashLen = 48;
                } else if (hashAlg.equals("SHA512")) {
                    hashLen = 64;
                }
                int comboLength = cipherBytes.length - decryptedSymKeyLen;
                byte[] encryptedComboBytes = new byte[comboLength];
                byte[] encryptedSymKey = new byte[decryptedSymKeyLen];
                System.arraycopy(cipherBytes, 0, encryptedComboBytes, 0, comboLength);
                System.arraycopy(cipherBytes, comboLength, encryptedSymKey, 0, decryptedSymKeyLen);

                byte[] decryptedSymKey = mainProcess.getSymKey(encryptedSymKey);
                jtaB.setCaretPosition(jtaB.getText().length());
                jtaB.append("\n---------------------------------------------------" + df.format(day) + "---------------------------------------------------\n");
                jtaB.append("----------------------------------------------------------验证消息----------------------------------------------------------\n");
                jtaB.append("解密得对称密钥：" + bytes2String(decryptedSymKey) + "\n");

                byte[] decryptedComboBytes = mainProcess.getComboBytes(encryptedComboBytes, decryptedSymKey);

                if (hashLen < ((Integer.valueOf(RSABitLength) / 8) - 3)) {
                    encryptedSigLen = Integer.valueOf(RSABitLength) / 8;
                } else {
                    encryptedSigLen = Integer.valueOf(RSABitLength) / 8 * 2;
                }
                int messageLen = decryptedComboBytes.length - encryptedSigLen;
                byte[] decryptedMessage = new byte[messageLen];
                byte[] encryptedSigBytes = new byte[encryptedSigLen];
                System.arraycopy(decryptedComboBytes, 0, decryptedMessage, 0, messageLen);
                System.arraycopy(decryptedComboBytes, messageLen, encryptedSigBytes, 0, encryptedSigLen);
                byte[] decryptedSigBytes = mainProcess.getEncryptedSig(encryptedSigBytes);

                jtaB.append("解密得" + hashAlg + "：" + bytes2String(decryptedSigBytes) + "\n");
                jtaB.append("解密得消息：" + bytes2String(decryptedMessage) + "\n");
                byte[] hashBytes = mainProcess.getHash(decryptedMessage);
                jtaB.append("用A公钥计算解密后消息的" + hashAlg + "：" + bytes2String(hashBytes) + "\n");
                jtaB.append("-----------------------------------------------------------------------------------------------------------------------------\n");


            }
        });

        jbDReset.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                plainPanel.setVisible(true);
                cipherPanel.setVisible(false);
                jtaCipher.setText("");
                jtaPlain.setText("");
            }
        });


    }

}

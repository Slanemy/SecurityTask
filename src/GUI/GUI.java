package GUI;


import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;


public class GUI {
    //GUI各种组件的显示程序
    private static final int DEFAULT_WIDTH = 1200;
    private static final int DEFAULT_HEIGHT = 800;
    private static final int DEFAULT_POSITION_X = 300;
    private static final int DEFAULT_POSITION_Y = 200;
    private static final String ICON = "E:\\SecurityTask\\assets\\icon.jpg";
    private static final String FLOW = "E:\\SecurityTask\\assets\\flow.jpg";
    private static final int OFFSET_Y = 34;
    private static final int OFFSET_X = 90;
    private static final int LINE_Y = 36;
    private static final int LINE_X = 120;
    public JFrame frame;

    public GUI() {
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

        //添加框图
        JPanel gImage = new JPanel() {

            protected void paintComponent(Graphics g) {
                ImageIcon icon = new ImageIcon(FLOW);
                Image img = icon.getImage();
                g.drawImage(img, 0, 0, icon.getIconWidth(),
                        icon.getIconHeight(), icon.getImageObserver());

            }

        };
        gImage.setBounds(0, 0, DEFAULT_WIDTH, 250);
        contentPane.add(gImage);


        //选择参数部分
        JPanel setup = new JPanel();
        setup.setBounds(0, 251, 400, 250);
        Border setBorder = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),"选择参数");
        setup.setBorder(setBorder);
        contentPane.add(setup);
        setup.setLayout(null);

        JLabel lblSymmetric = new JLabel("对称加密算法：");
        lblSymmetric.setFont(new Font("微软雅黑", Font.PLAIN, 14));
        lblSymmetric.setBounds(10, LINE_Y, 150, 23);
        setup.add(lblSymmetric);

        JRadioButton jrbDES = new JRadioButton("DES",true);
        jrbDES.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbDES.setBounds(LINE_X, LINE_Y, 80, 23);
        JRadioButton jrbAES = new JRadioButton("AES",false);
        jrbAES.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbAES.setBounds(LINE_X + OFFSET_X, LINE_Y, 100, 23);
        ButtonGroup symmetricGroup = new ButtonGroup();
        symmetricGroup.add(jrbDES);
        symmetricGroup.add(jrbAES);
        setup.add(jrbAES);
        setup.add(jrbDES);

        JLabel lblMode = new JLabel("分组加密模式：");
        lblMode.setFont(new Font("微软雅黑", Font.PLAIN, 14));
        lblMode.setBounds(10, LINE_Y + OFFSET_Y, 150, 23);
        setup.add(lblMode);

        JRadioButton jrbECB = new JRadioButton("ECB",true);
        jrbECB.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbECB.setBounds(LINE_X, LINE_Y + OFFSET_Y, 80, 23);
        JRadioButton jrbCBC = new JRadioButton("CBC",false);
        jrbCBC.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbCBC.setBounds(LINE_X + OFFSET_X, LINE_Y + OFFSET_Y, 100, 23);
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(jrbECB);
        modeGroup.add(jrbCBC);
        setup.add(jrbECB);
        setup.add(jrbCBC);

        JLabel lblHash = new JLabel("HASH算法：");
        lblHash.setFont(new Font("微软雅黑", Font.PLAIN, 14));
        lblHash.setBounds(25, LINE_Y + OFFSET_Y * 2, 150, 23);
        setup.add(lblHash);

        JRadioButton jrbMD5 = new JRadioButton("MD5",true);
        jrbMD5.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbMD5.setBounds(LINE_X, LINE_Y + OFFSET_Y * 2, 90, 23);
        JRadioButton jrbSHA224 = new JRadioButton("SHA-224",false);
        jrbSHA224.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbSHA224.setBounds(LINE_X + OFFSET_X, LINE_Y + OFFSET_Y * 2, 90, 23);
        JRadioButton jrbSHA256 = new JRadioButton("SHA-256",false);
        jrbSHA256.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbSHA256.setBounds(LINE_X, LINE_Y + OFFSET_Y * 3, 90, 23);
        JRadioButton jrbSHA384 = new JRadioButton("SHA-384",false);
        jrbSHA384.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbSHA384.setBounds(LINE_X + OFFSET_X, LINE_Y + OFFSET_Y * 3, 90, 23);
        JRadioButton jrbSHA512 = new JRadioButton("SHA-512",false);
        jrbSHA512.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrbSHA512.setBounds(LINE_X + OFFSET_X * 2, LINE_Y + OFFSET_Y * 3, 90, 23);

        ButtonGroup hashGroup = new ButtonGroup();
        hashGroup.add(jrbMD5);
        hashGroup.add(jrbSHA224);
        hashGroup.add(jrbSHA256);
        hashGroup.add(jrbSHA512);
        hashGroup.add(jrbSHA384);
        setup.add(jrbMD5);
        setup.add(jrbSHA224);
        setup.add(jrbSHA256);
        setup.add(jrbSHA384);
        setup.add(jrbSHA512);

        JLabel lblRSA = new JLabel("RSA位数：");
        lblRSA.setFont(new Font("微软雅黑", Font.PLAIN, 14));
        lblRSA.setBounds(39, LINE_Y + OFFSET_Y * 4, 150, 23);
        setup.add(lblRSA);

        JRadioButton jrb1024 = new JRadioButton("1024",true);
        jrb1024.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrb1024.setBounds(LINE_X, LINE_Y + OFFSET_Y * 4, 90, 23);
        JRadioButton jrb2048 = new JRadioButton("2048",false);
        jrb2048.setFont(new Font("Time News Roman", Font.PLAIN, 14));
        jrb2048.setBounds(LINE_X + OFFSET_X, LINE_Y + OFFSET_Y * 4, 90, 23);
        ButtonGroup RSABitsGroup = new ButtonGroup();
        RSABitsGroup.add(jrb1024);
        RSABitsGroup.add(jrb2048);
        setup.add(jrb1024);
        setup.add(jrb2048);

        JButton attrConfirm = new JButton("确定");
        attrConfirm.setBounds(120,LINE_Y + OFFSET_Y * 5,70,23);
        setup.add(attrConfirm);

        JButton attrReset = new JButton("重置");
        attrReset.setBounds(220,LINE_Y + OFFSET_Y * 5,70,23);
        setup.add(attrReset);

    }
}

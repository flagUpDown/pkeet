package mhzy15pkeetfa;

public class Test {

    public static void main(String[] args) throws Exception {
        // 存在用户1和用户2, 分别生成各自的公私钥对
        PublicPrivateKeyPair ppkp_1 = new PublicPrivateKeyPair();
        PublicPrivateKeyPair ppkp_2 = new PublicPrivateKeyPair();

        // 生成一个关键字
        Message m = new Message("Holy Grail");

        // 对同一个关键字使用不同的公钥进行加密
        Ciphertext C_1 = new Ciphertext(m, ppkp_1);
        Ciphertext C_2 = new Ciphertext(m, ppkp_2);

        // 测试密文能否正常解密
        if (!m.isDecrypt(C_1, ppkp_1) || !m.isDecrypt(C_2, ppkp_2)) {
            throw new Exception("解密失败!!!");
        }

        // 进行Type-1授权
        Token1 ti_1 = new Token1(ppkp_1);
        Token1 tj_1 = new Token1(ppkp_2);

        // 进行Type-2授权
        Token2 ti_2 = new Token2(C_1, ppkp_1);
        Token2 tj_2 = new Token2(C_2, ppkp_2);

        // 进行Type-3授权
        Token3 ti_3 = new Token3(C_1, C_2, ppkp_1);
        Token3 tj_3 = new Token3(C_2, C_1, ppkp_2);

        // 进行Type-4授权
        Token2 ti_4 = new Token2(C_1, ppkp_1);
        Token1 tj_4 = new Token1(ppkp_2);

        // 进行等值测试
        if (!EqualityTest.test1(ti_1, C_1, tj_1, C_2)) { // 进行Type-1等值测试
            System.out.print("等值测试失败!!!");
        } else if (!EqualityTest.test2(ti_2, C_1, tj_2, C_2)) { // 进行Type-2等值测试
            System.out.print("等值测试失败!!!");
        } else if (!EqualityTest.test3(ti_3, C_1, tj_3, C_2)) { // 进行Type-3等值测试
            System.out.print("等值测试失败!!!");
        } else if (!EqualityTest.test4(ti_4, C_1, tj_4, C_2)) { // 进行Type-3等值测试
            System.out.print("等值测试失败!!!");
        } else {
            System.out.print("等值测试成功!!!");
        }
    }

}

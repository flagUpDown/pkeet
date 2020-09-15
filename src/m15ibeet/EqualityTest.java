package m15ibeet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

public class EqualityTest {

    public static void main(String[] args) throws Exception {
        // 存在用户1和用户2, 分别生成各自的公私钥对
        PublicPrivateKeyPair ppkp_1 = new PublicPrivateKeyPair("user1");
        PublicPrivateKeyPair ppkp_2 = new PublicPrivateKeyPair("user2");

        // 生成一个关键字
        Message m = new Message("Holy Grail");

        // 对同一个关键字使用不同的公钥进行加密
        Ciphertext C_1 = new Ciphertext(m, ppkp_1);
        Ciphertext C_2 = new Ciphertext(m, ppkp_2);

        // 测试密文能否正常解密
        if (!m.isDecrypt(C_1, ppkp_1) || !m.isDecrypt(C_2, ppkp_2)) {
            throw new Exception("解密失败!!!");
        }

        // 进行授权
        Token t1 = new Token(ppkp_1);
        Token t2 = new Token(ppkp_2);

        // 进行等值测试
        Element X_1 = ParamsA.pairing.pairing(C_1.C2, t1.t);
        X_1 = C_1.C3.div(ParamsA.G1.newElementFromHash(X_1.toBytes(), 0, X_1.toBytes().length));

        Element X_2 = ParamsA.pairing.pairing(C_2.C2, t2.t);
        X_2 = C_2.C3.div(ParamsA.G1.newElementFromHash(X_2.toBytes(), 0, X_2.toBytes().length));

        Element e_1 = ParamsA.pairing.pairing(C_1.C1, X_2);
        Element e_2 = ParamsA.pairing.pairing(C_2.C1, X_1);
        if (e_1.isEqual(e_2)) {
            System.out.println("等值测试成功!!!");
        } else {
            System.out.println("等值测试失败!!!");
        }
    }

}

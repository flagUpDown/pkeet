package t11fgpkeet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

public class EqualityTest {

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

        // 进行授权
        Token T = new Token(ppkp_1, ppkp_2);

        // 进行等值测试
        Element e_1 = ParamsA.pairing.pairing(C_1.C4, T.t1);
        e_1 = e_1.div(ParamsA.pairing.pairing(C_1.C2, T.t2));
        Element e_2 = ParamsA.pairing.pairing(C_2.C4, T.t1);
        e_2 = e_2.div(ParamsA.pairing.pairing(C_2.C2, T.t3));
        
        if (e_1.isEqual(e_2)) {
            System.out.print("等值测试成功!!!");
        } else {
            System.out.print("等值测试失败!!!");
        }
    }

}

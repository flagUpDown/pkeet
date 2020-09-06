package t12AoNpkeet;

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
        Token T_1 = new Token(ppkp_1);
        Token T_2 = new Token(ppkp_2);

        // 进行等值测试
        Element e_1_hash = ParamsA.Zr
                .newElementFromBytes(utils.HashUtils.notSafeHash(32, C_1.C2.powZn(T_1.t).toString()));
        Element e_1 = C_1.C4.mul(ParamsA.g.powZn(e_1_hash.negate()));
        Element e_2_hash = ParamsA.Zr
                .newElementFromBytes(utils.HashUtils.notSafeHash(32, C_2.C2.powZn(T_2.t).toString()));
        Element e_2 = C_2.C4.mul(ParamsA.g.powZn(e_2_hash.negate()));
        
        if (e_1.isEqual(e_2)) {
            System.out.print("等值测试成功!!!");
        } else {
            System.out.print("等值测试失败!!!");
        }
    }

}

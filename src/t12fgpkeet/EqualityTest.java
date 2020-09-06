package t12fgpkeet;

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
        // r是由用户1和用户2协商生成
        Element r = ParamsA.Zr.newRandomElement().getImmutable();
        Token T = new Token(ppkp_1, ppkp_2, r);

        // 进行等值测试

        // 在代理服务器Vx上计算X1, 并随机生成rx, 计算rx*X1, 将结果交给Vy
        Element X1 = ParamsA.pairing.pairing(C_1.C4, T.Vx.v1);
        X1 = X1.div(ParamsA.pairing.pairing(C_1.C2, T.Vx.v2));
        Element rx = ParamsA.GT.newRandomElement().getImmutable();
        X1 = X1.mul(rx);

        // 在代理服务器Vy上计算X2, 并随机生成ry, 计算ry*X2, 将结果交给Vx
        Element X2 = ParamsA.pairing.pairing(C_2.C4, T.Vy.v1);
        X2 = X2.div(ParamsA.pairing.pairing(C_2.C2, T.Vy.v3));
        Element ry = ParamsA.GT.newRandomElement().getImmutable();
        X2 = X2.mul(ry);

        // 在代理服务器Vx上计算e_1
        Element e_1 = X2.div(ParamsA.pairing.pairing(C_2.C2, T.Vx.v3));
        e_1 = e_1.mul(rx);

        // 在代理服务器Vx上计算e_1
        Element e_2 = X1.div(ParamsA.pairing.pairing(C_1.C2, T.Vy.v2));
        e_2 = e_2.mul(ry);

        if (e_1.isEqual(e_2)) {
            System.out.print("等值测试成功!!!");
        } else {
            System.out.print("等值测试失败!!!");
        }
    }

}

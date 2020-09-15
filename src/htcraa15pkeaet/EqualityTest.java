package htcraa15pkeaet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

public class EqualityTest {

    public static void main(String[] args) throws Exception {
        // 存在用户1和用户2, 分别生成各自的公私钥对
        PublicPrivateKeyPair ppkp_1 = new PublicPrivateKeyPair();
        PublicPrivateKeyPair ppkp_2 = new PublicPrivateKeyPair();

        // 生成进行等值测试的服务器的密钥
        PublicPrivateKeyPair ppkp_t = new PublicPrivateKeyPair();

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

        Token_r Tr_1 = new Token_r(ppkp_1, ppkp_t);
        Token_c Tc_1 = new Token_c(ppkp_1, ppkp_t, C_1);

        Token_r Tr_2 = new Token_r(ppkp_2, ppkp_t);
        Token_c Tc_2 = new Token_c(ppkp_2, ppkp_t, C_2);

        // 对授权进行验证
        if (!(Token_r.verify(Tr_1, ppkp_1, ppkp_t) && Token_c.verify(Tc_1, ppkp_1, ppkp_t, C_1)
                && Token_r.verify(Tr_2, ppkp_2, ppkp_t) && Token_c.verify(Tc_2, ppkp_2, ppkp_t, C_2))) {
            throw new Exception("对Token进行验证失败!!!");
        }

        // 进行等值测试

        // 方法1
        Element z_1 = Tr_1.t1.powZn(ppkp_t.sk_y);
        z_1 = ParamsA.Zr.newElementFromHash(z_1.toBytes(), 0, z_1.toBytes().length);
        z_1 = C_1.C1.powZn(Tr_1.t2.div(z_1));
        z_1 = ParamsA.G1.newElementFromHash(z_1.toBytes(), 0, z_1.toBytes().length);
        z_1 = C_1.C2.div(z_1);

        Element z_2 = Tr_2.t1.powZn(ppkp_t.sk_y);
        z_2 = ParamsA.Zr.newElementFromHash(z_2.toBytes(), 0, z_2.toBytes().length);
        z_2 = C_2.C1.powZn(Tr_2.t2.div(z_2));
        z_2 = ParamsA.G1.newElementFromHash(z_2.toBytes(), 0, z_2.toBytes().length);
        z_2 = C_2.C2.div(z_2);

        Element e_1 = ParamsA.pairing.pairing(C_1.C1, z_2);
        Element e_2 = ParamsA.pairing.pairing(C_2.C1, z_1);

        if (e_1.isEqual(e_2)) {
            System.out.println("等值测试成功!!!");
        } else {
            System.out.println("等值测试失败!!!");
        }

        // 方法二
        z_1 = Tc_1.t1.powZn(ppkp_t.sk_y);
        z_1 = ParamsA.G1.newElementFromHash(z_1.toBytes(), 0, z_1.toBytes().length);
        z_1 = Tc_1.t2.div(z_1);
        z_1 = ParamsA.G1.newElementFromHash(z_1.toBytes(), 0, z_1.toBytes().length);
        z_1 = C_1.C2.div(z_1);

        z_2 = Tc_2.t1.powZn(ppkp_t.sk_y);
        z_2 = ParamsA.G1.newElementFromHash(z_2.toBytes(), 0, z_2.toBytes().length);
        z_2 = Tc_2.t2.div(z_2);
        z_2 = ParamsA.G1.newElementFromHash(z_2.toBytes(), 0, z_2.toBytes().length);
        z_2 = C_2.C2.div(z_2);

        e_1 = ParamsA.pairing.pairing(C_1.C1, z_2);
        e_2 = ParamsA.pairing.pairing(C_2.C1, z_1);

        if (e_1.isEqual(e_2)) {
            System.out.println("等值测试成功!!!");
        } else {
            System.out.println("等值测试失败!!!");
        }
    }

}

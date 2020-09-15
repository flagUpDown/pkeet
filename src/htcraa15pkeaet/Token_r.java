package htcraa15pkeaet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

// 用户创建Token的过程就是授权的过程
// 创建接收者的令牌
public class Token_r {
    public Element t1;
    public Element t2;

    Token_r(PublicPrivateKeyPair ppkp_r, PublicPrivateKeyPair ppkp_t) {
        Element theta = ParamsA.Zr.newRandomElement().getImmutable();
        t1 = ParamsA.g.powZn(theta);

        t2 = ppkp_t.pk_y.powZn(theta);
        t2 = ParamsA.Zr.newElementFromHash(t2.toBytes(), 0, t2.toBytes().length);
        t2 = ppkp_r.sk_x.mul(t2);
    }

    public static boolean verify(Token_r t, PublicPrivateKeyPair ppkp_r, PublicPrivateKeyPair ppkp_t) {
        Element ppkp_r_sk_x_de = t.t1.powZn(ppkp_t.sk_y);
        ppkp_r_sk_x_de = ParamsA.Zr.newElementFromHash(ppkp_r_sk_x_de.toBytes(), 0, ppkp_r_sk_x_de.toBytes().length);
        ppkp_r_sk_x_de = t.t2.div(ppkp_r_sk_x_de);
        if (ppkp_r.pk_x.isEqual(ParamsA.g.powZn(ppkp_r_sk_x_de))) {
            return true;
        }
        return false;
    }
}

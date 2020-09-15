package htcraa15pkeaet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

// 用户创建Token的过程就是授权的过程
// 密文的令牌
public class Token_c {
    public Element t1;
    public Element t2;

    Token_c(PublicPrivateKeyPair ppkp_r, PublicPrivateKeyPair ppkp_t, Ciphertext C) {
        Element theta = ParamsA.Zr.newRandomElement().getImmutable();
        t1 = ParamsA.g.powZn(theta);

        t2 = ppkp_t.pk_y.powZn(theta);
        t2 = ParamsA.G1.newElementFromHash(t2.toBytes(), 0, t2.toBytes().length);
        t2 = C.C1.powZn(ppkp_r.sk_x).mul(t2);
    }

    public static boolean verify(Token_c t, PublicPrivateKeyPair ppkp_r, PublicPrivateKeyPair ppkp_t, Ciphertext C) {
        Element z = t.t1.powZn(ppkp_t.sk_y);
        z = ParamsA.G1.newElementFromHash(z.toBytes(), 0, z.toBytes().length);
        z = t.t2.div(z);
        if (ParamsA.pairing.pairing(z, ParamsA.g)
                .isEqual(ParamsA.pairing.pairing(C.C1, ParamsA.g.powZn(ppkp_r.sk_x)))) {
            return true;
        }
        return false;
    }
}

package t11fgpkeet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/* 用户创建Token的过程就是授权的过程
 * t1 = g2^r
 * t2 = g2^{y_1*r}
 * t3 = g2^{y_2*r}
 */
public class Token {
    public Element t1;
    public Element t2;
    public Element t3;

    Token(PublicPrivateKeyPair ppkp1, PublicPrivateKeyPair ppkp2) {
        // r是由用户1和用户2协商生成
        Element r = ParamsA.Zr.newRandomElement().getImmutable();

        this.t1 = ParamsA.g2.powZn(r);
        this.t2 = ppkp1.pk_y.powZn(r);
        this.t3 = ppkp2.pk_y.powZn(r);
    }
}

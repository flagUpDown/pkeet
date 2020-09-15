package xwzclf17vpkeet;

import it.unisa.dia.gas.jpbc.Element;

/*
 * Type-3的Token
 * 用户创建Token的过程就是授权的过程
 */
public class Token3 {
    public Element t1;
    public Element t2;
    public Element t3;

    public Element Yj;

    Token3(Ciphertext Ci, PublicPrivateKeyPair ppkp1, PublicPrivateKeyPair ppkp2) {
        Yj = ppkp2.pk_y;
        t1 = Ci.C2.mul(Yj).powZn(ppkp1.sk_y);
        t2 = ppkp2.pk_x.powZn(ppkp1.sk_x);
        t3 = ppkp2.pk_x.powZn(ppkp1.sk_x.mul(ppkp1.sk_y));
    }
}

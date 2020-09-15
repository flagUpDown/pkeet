package xwzclf17vpkeet;

import it.unisa.dia.gas.jpbc.Element;

/*
 * Type-2的Token
 * 用户创建Token的过程就是授权的过程
 */
public class Token2 {
    public Element t1;
    public Element t2;

    Token2(PublicPrivateKeyPair ppkp1, PublicPrivateKeyPair ppkp2) {
        t1 = ppkp2.pk_x.powZn(ppkp1.sk_x);
        t2 = ppkp2.pk_x.powZn(ppkp1.sk_x.mul(ppkp1.sk_y));
    }
}

package mhzy15pkeetfa;

import it.unisa.dia.gas.jpbc.Element;

/*
 * Type-1的Token
 * 用户创建Token的过程就是授权的过程
 */
public class Token1 {
    public Element t1;

    Token1(PublicPrivateKeyPair ppkp) {
        this.t1 = ppkp.sk_x;
    }
}

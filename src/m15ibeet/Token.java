package m15ibeet;

import it.unisa.dia.gas.jpbc.Element;

/*
 * Type-1的Token
 * 用户创建Token的过程就是授权的过程
 */
public class Token {
    public Element t;

    Token(PublicPrivateKeyPair ppkp) {
        this.t = ppkp.sk_x;
    }
}

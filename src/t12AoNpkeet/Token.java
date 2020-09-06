package t12AoNpkeet;

import it.unisa.dia.gas.jpbc.Element;

// 用户创建Token的过程就是授权的过程
public class Token {
    public Element t;

    Token(PublicPrivateKeyPair ppkp) {
        t = ppkp.sk_y;
    }
}

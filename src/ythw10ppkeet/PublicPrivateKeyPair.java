package ythw10ppkeet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 用户生成公私钥对(pk,sk)
 */
public class PublicPrivateKeyPair {
    public Element sk;
    public Element pk;

    PublicPrivateKeyPair() {
        sk = ParamsA.Zr.newRandomElement().getImmutable();
        pk = ParamsA.g.powZn(sk).getImmutable();
    }
}

package htcls14cbapkeet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 用户生成公私钥对(pk,sk)
 */
public class PublicPrivateKeyPair {
    public Element sk_x;
    public Element pk_x;

    PublicPrivateKeyPair() {
        sk_x = ParamsA.Zr.newRandomElement().getImmutable();
        pk_x = ParamsA.g.powZn(sk_x).getImmutable();
    }
}

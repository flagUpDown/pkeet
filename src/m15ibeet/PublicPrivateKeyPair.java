package m15ibeet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 用户生成公私钥对(pk,sk)
 */
public class PublicPrivateKeyPair {
    public Element h_ID;
    public Element U1;
    public Element U2;

    public Element sk_x;
    public Element sk_y;

    PublicPrivateKeyPair(String id) {
        Element s1 = ParamsA.Zr.newRandomElement().getImmutable();
        Element s2 = ParamsA.Zr.newRandomElement().getImmutable();
        h_ID = ParamsA.G1.newElementFromHash(id.getBytes(), 0, id.getBytes().length).getImmutable();
        U1 = ParamsA.pairing.pairing(h_ID, ParamsA.g.powZn(s1)).getImmutable();
        U2 = ParamsA.pairing.pairing(h_ID, ParamsA.g.powZn(s2)).getImmutable();
        sk_x = h_ID.powZn(s1).getImmutable();
        sk_y = h_ID.powZn(s2).getImmutable();
    }
}
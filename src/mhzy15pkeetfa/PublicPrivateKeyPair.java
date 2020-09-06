package mhzy15pkeetfa;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 用户生成公私钥对(pk,sk)
 */
public class PublicPrivateKeyPair {
    public Element sk_x;
    public Element sk_y;
    public Element sk_z;

    public Element pk_x;
    public Element pk_y;
    public Element pk_z;

    PublicPrivateKeyPair() {
        sk_x = ParamsA.Zr.newRandomElement().getImmutable();
        sk_y = ParamsA.Zr.newRandomElement().getImmutable();
        sk_z = ParamsA.Zr.newRandomElement().getImmutable();

        pk_x = ParamsA.g.powZn(sk_x).getImmutable();
        pk_y = ParamsA.g.powZn(sk_y).getImmutable();
        pk_z = ParamsA.g.powZn(sk_z).getImmutable();
    }
}

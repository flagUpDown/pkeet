package ythw10ppkeet;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 密文 C = (U,V,W); 明文 m \in G_1^*
 * r <--- Zr
 * U = g^r; V = m^r; W = H(U,V,pk^r) \oplus (m||r)
 */
public class Ciphertext {
    public Element U;
    public Element V;
    // W分为两个部分W_m,W_r
    public byte[] W_m;
    public byte[] W_r;

    private Element r;

    Ciphertext(Message m, PublicPrivateKeyPair ppkp) {
        r = ParamsA.Zr.newRandomElement().getImmutable();
        U = ParamsA.g.powZn(r);
        V = m.mElement.powZn(r);
        Element W = ppkp.pk.powZn(r);
        byte[] W_hash = utils.HashUtils.notSafeHash(m.mByte.length + r.toBytes().length, U.toString(), V.toString(),
                W.toString());
        W_m = utils.ByteArrayUtils.xor(m.mByte, Arrays.copyOfRange(W_hash, 0, m.mByte.length));
        W_r = utils.ByteArrayUtils.xor(r.toBytes(),
                Arrays.copyOfRange(W_hash, m.mByte.length, m.mByte.length + r.toBytes().length));
    }
}

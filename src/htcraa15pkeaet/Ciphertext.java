package htcraa15pkeaet;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 密文 C = (C1,C2,C3)
 * r <-- Zr
 * C1 = g^r
 * C2 = m^r * H1(g^{xr})
 * C3 = H1(g^{yr}) \xor m||r
 */
public class Ciphertext {
    public Element C1;
    public Element C2;
    // C3分为两个部分C3_m, C3_r
    public byte[] C3_m;
    public byte[] C3_r;

    private Element r;

    Ciphertext(Message m, PublicPrivateKeyPair ppkp) {
        r = ParamsA.Zr.newRandomElement().getImmutable();

        C1 = ParamsA.g.powZn(r).getImmutable();
        C2 = ppkp.pk_x.powZn(r);
        C2 = ParamsA.G1.newElementFromHash(C2.toBytes(), 0, C2.toBytes().length);
        C2 = m.mElement.powZn(r).mul(C2);

        byte[] C3_hash = utils.HashUtils.notSafeHash(m.mByte.length + r.toBytes().length,
                ppkp.pk_y.powZn(r).toString());
        C3_m = utils.ByteArrayUtils.xor(m.mByte, Arrays.copyOfRange(C3_hash, 0, m.mByte.length));
        C3_r = utils.ByteArrayUtils.xor(r.toBytes(),
                Arrays.copyOfRange(C3_hash, m.mByte.length, m.mByte.length + r.toBytes().length));
    }
}

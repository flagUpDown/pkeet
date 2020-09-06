package t11fgpkeet;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 密文 C = (C1,C2,C3,C4,C5)
 * u,v <-- Zr
 * C1 = g^u
 * C2 = g2^v
 * C3 = H2(g^{ux}) \xor m||u
 * C4 = g2^{vy})*H3(m)
 * C5 = H3(C1||C2||C3||C4||m||u)
 */
public class Ciphertext {
    public Element C1;
    public Element C2;
    // C3分为两个部分C3_m, C3_u
    public byte[] C3_m;
    public byte[] C3_u;
    public Element C4;
    public byte[] C5;

    private Element u;
    private Element v;

    Ciphertext(Message m, PublicPrivateKeyPair ppkp) {
        u = ParamsA.Zr.newRandomElement().getImmutable();
        v = ParamsA.Zr.newRandomElement().getImmutable();

        C1 = ParamsA.g.powZn(u).getImmutable();
        C2 = ParamsA.g2.powZn(v).getImmutable();
        byte[] C3_hash = utils.HashUtils.notSafeHash(m.mByte.length + u.toBytes().length,
                ppkp.pk_x.powZn(u).toString());
        C3_m = utils.ByteArrayUtils.xor(m.mByte, Arrays.copyOfRange(C3_hash, 0, m.mByte.length));
        C3_u = utils.ByteArrayUtils.xor(u.toBytes(),
                Arrays.copyOfRange(C3_hash, m.mByte.length, m.mByte.length + u.toBytes().length));
        C4 = ppkp.pk_y.powZn(v).mul(m.mElement);
        C5 = utils.HashUtils.notSafeHash(32, C1.toString(), C2.toString(), C3_m.toString(), C3_u.toString(),
                C4.toString(), m.m, u.toString());
    }
}

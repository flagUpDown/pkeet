package xwzclf17vpkeet;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 密文 C = (C1,C2,C3,C4,C5)
 * r1,r2 <-- Zr
 * C1 = g2^r1
 * C2 = g^r2
 * C3 = H2(pk_x^{r1}) \xor (m||r1)
 * C4 = pk_y^{r2} * H3(m)
 * C5 = H1(C1 || C2 || C3 || C4|| m || r1) 
 */
public class Ciphertext {
    public Element C1;
    public Element C2;
    // C3分为两个部分C3_m, C3_r1
    public byte[] C3_m;
    public byte[] C3_r1;
    public Element C4;
    public byte[] C5;

    private Element r1;
    private Element r2;

    Ciphertext(Message m, PublicPrivateKeyPair ppkp) {
        r1 = ParamsA.Zr.newRandomElement().getImmutable();
        r2 = ParamsA.Zr.newRandomElement().getImmutable();

        C1 = ParamsA.g2.powZn(r1).getImmutable();
        C2 = ParamsA.g.powZn(r2).getImmutable();

        String pk_x_r = ppkp.pk_x.powZn(r1).toString();
        byte[] C3_hash = utils.HashUtils.notSafeHash(m.mByte.length + r1.toBytes().length, pk_x_r);
        C3_m = utils.ByteArrayUtils.xor(m.mByte, Arrays.copyOfRange(C3_hash, 0, m.mByte.length));
        C3_r1 = utils.ByteArrayUtils.xor(r1.toBytes(),
                Arrays.copyOfRange(C3_hash, m.mByte.length, m.mByte.length + r1.toBytes().length));

        C4 = ppkp.pk_y.powZn(r2).mul(m.mElement);
        C5 = utils.HashUtils.notSafeHash(32, C1.toString(), C2.toString(), C3_m.toString(), C3_r1.toString(),
                C4.toString(), m.m, r1.toString());
    }
}

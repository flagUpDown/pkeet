package mhzy15pkeetfa;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 密文 C = (C1,C2,C3,C4,C5)
 * r1,r2 <-- Zr
 * C1 = g^r1
 * C2 = g^r2
 * C3 = (M^r1 || (M*Y)^r1) \xor H1(pk_x^r2)
 * C4 = H2(C1||C2||C3||pk_z^r2) \xor (M||r1)
 */
public class Ciphertext {
    public Element C1;
    public Element C2;
    // C3分为两个部分C3_mr, C3_myr
    public byte[] C3_mr;
    public byte[] C3_myr;
    // C4分为两个部分C4_m, C4_r1
    public byte[] C4_m;
    public byte[] C4_r1;

    private Element r1;
    private Element r2;

    Ciphertext(Message m, PublicPrivateKeyPair ppkp) {
        r1 = ParamsA.Zr.newRandomElement().getImmutable();
        r2 = ParamsA.Zr.newRandomElement().getImmutable();

        C1 = ParamsA.g.powZn(r1).getImmutable();
        C2 = ParamsA.g.powZn(r2).getImmutable();
        byte[] mr = m.mElement.powZn(r1).toBytes();
        byte[] myr = m.mElement.mul(ppkp.pk_y).powZn(r1).toBytes();
        byte[] C3_hash = utils.HashUtils.notSafeHash(mr.length + myr.length, ppkp.pk_x.powZn(r2).toString());
        C3_mr = utils.ByteArrayUtils.xor(mr, Arrays.copyOfRange(C3_hash, 0, mr.length));
        C3_myr = utils.ByteArrayUtils.xor(myr, Arrays.copyOfRange(C3_hash, mr.length, mr.length + myr.length));
        byte[] C4_hash = utils.HashUtils.notSafeHash(m.mByte.length + r1.toBytes().length, C1.toString(), C2.toString(),
                C3_mr.toString(), C3_myr.toString(), ppkp.pk_z.powZn(r2).toString());
        C4_m = utils.ByteArrayUtils.xor(m.mByte, Arrays.copyOfRange(C4_hash, 0, m.mByte.length));
        C4_r1 = utils.ByteArrayUtils.xor(r1.toBytes(),
                Arrays.copyOfRange(C4_hash, m.mByte.length, m.mByte.length + r1.toBytes().length));
    }
}

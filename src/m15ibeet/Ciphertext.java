package m15ibeet;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 密文 C = (C1,C2,C3)
 * r1, r2, r3 <-- Zr
 * U1 = (sk,g)
 * U2 = (sk,g2)
 * C1 = g^r1
 * C2 = g^r2
 * C3 = M^r1 * H2(U1^r2)
 * C4 = g^r3
 * C5 = 
 */
public class Ciphertext {
    public Element C1;
    public Element C2;
    public Element C3;
    public Element C4;
    // C5分为两个部分C5_m, C5_r1
    public byte[] C5_m;
    public byte[] C5_r1;

    private Element r1;
    private Element r2;
    private Element r3;

    Ciphertext(Message m, PublicPrivateKeyPair ppkp) {
        r1 = ParamsA.Zr.newRandomElement().getImmutable();
        r2 = ParamsA.Zr.newRandomElement().getImmutable();
        r3 = ParamsA.Zr.newRandomElement().getImmutable();

        C1 = ParamsA.g.powZn(r1).getImmutable();
        C2 = ParamsA.g.powZn(r2).getImmutable();
        byte[] U1_r2 = ppkp.U1.powZn(r2).toBytes();
        C3 = m.mElement.powZn(r1).mul(ParamsA.G1.newElementFromHash(U1_r2, 0, U1_r2.length)).getImmutable();
        C4 = ParamsA.g.powZn(r3).getImmutable();

        byte[] C5_hash = utils.HashUtils.notSafeHash(m.mByte.length + r1.toBytes().length,
                ppkp.U2.powZn(r3).toString());
        C5_m = utils.ByteArrayUtils.xor(m.mByte, Arrays.copyOfRange(C5_hash, 0, m.mByte.length));
        C5_r1 = utils.ByteArrayUtils.xor(r1.toBytes(),
                Arrays.copyOfRange(C5_hash, m.mByte.length, m.mByte.length + r1.toBytes().length));
    }
}

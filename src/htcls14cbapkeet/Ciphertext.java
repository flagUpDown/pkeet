package htcls14cbapkeet;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;
import utils.ByteArrayUtils;
import utils.HashUtils;

/*
 * 密文 C = (C1,C2)
 * r <-- Zr
 * u = H1(m || r || H3(m))
 * C1 = g^u
 * C2 = H2(y^u) \xor H1(m || r || H3(m))
 */
public class Ciphertext {
    public Element C1;
    // C3分为两个部分C3_m, C3_r, C3_hm
    public byte[] C3_m;
    public byte[] C3_r;
    public byte[] C3_hm;

    private Element r;
    private Element u;

    Ciphertext(Message m, PublicPrivateKeyPair ppkp) {
        r = ParamsA.Zr.newRandomElement().getImmutable();
        byte[] m_hash = HashUtils.notSafeHash(32, m.m);
        byte[] mrhm = (m.m + r.toString() + m_hash.toString()).getBytes();
        u = ParamsA.Zr.newElementFromHash(mrhm, 0, mrhm.length).getImmutable();
        C1 = ParamsA.g.powZn(u);

        byte[] C2_hash = HashUtils.notSafeHash(m.mByte.length + r.toBytes().length + m_hash.length,
                ppkp.pk_x.powZn(u).toString());
        C3_m = ByteArrayUtils.xor(m.mByte, Arrays.copyOfRange(C2_hash, 0, m.mByte.length));
        C3_r = ByteArrayUtils.xor(r.toBytes(),
                Arrays.copyOfRange(C2_hash, m.mByte.length, m.mByte.length + r.toBytes().length));
        C3_hm = ByteArrayUtils.xor(m_hash, Arrays.copyOfRange(C2_hash, m.mByte.length + r.toBytes().length,
                m.mByte.length + r.toBytes().length + m_hash.length));
    }
}

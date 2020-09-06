package mhzy15pkeetfa;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 明文
 */
public class Message {
    public String m;
    public byte[] mByte;
    public Element mElement;

    Message(String m) {
        this.m = m;
        this.mByte = m.getBytes();
        this.mElement = ParamsA.G1.newElementFromHash(mByte, 0, mByte.length).getImmutable();
    }

    public boolean isDecrypt(Ciphertext C, PublicPrivateKeyPair ppkp) {
        byte[] C4_hash = utils.HashUtils.notSafeHash(C.C4_m.length + C.C4_r1.length, C.C1.toString(), C.C2.toString(),
                C.C3_mr.toString(), C.C3_myr.toString(), C.C2.powZn(ppkp.sk_z).toString());
        byte[] m_decrypt = utils.ByteArrayUtils.xor(C.C4_m, Arrays.copyOfRange(C4_hash, 0, C.C4_m.length));
        byte[] r1_decrypt = utils.ByteArrayUtils.xor(C.C4_r1,
                Arrays.copyOfRange(C4_hash, C.C4_m.length, C.C4_m.length + C.C4_r1.length));
        Element m_de_elem = ParamsA.G1.newElementFromHash(m_decrypt, 0, m_decrypt.length).getImmutable();
        Element r1_de_elem = ParamsA.Zr.newElementFromBytes(r1_decrypt).getImmutable();
        byte[] mr = m_de_elem.powZn(r1_de_elem).toBytes();
        byte[] myr = m_de_elem.mul(ppkp.pk_y).powZn(r1_de_elem).toBytes();
        byte[] C3_hash = utils.HashUtils.notSafeHash(mr.length + myr.length, C.C2.powZn(ppkp.sk_x).toString());
        mr = utils.ByteArrayUtils.xor(mr, Arrays.copyOfRange(C3_hash, 0, mr.length));
        myr = utils.ByteArrayUtils.xor(myr, Arrays.copyOfRange(C3_hash, mr.length, mr.length + myr.length));
        if (C.C1.isEqual(ParamsA.g.powZn(r1_de_elem)) && Arrays.equals(mr, C.C3_mr) && Arrays.equals(myr, C.C3_myr)) {
            return true;
        }
        return false;
    }
}

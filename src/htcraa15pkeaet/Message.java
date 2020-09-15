package htcraa15pkeaet;

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
        byte[] C3_hash = utils.HashUtils.notSafeHash(C.C3_m.length + C.C3_r.length, C.C1.powZn(ppkp.sk_y).toString());
        byte[] m_decrypt = utils.ByteArrayUtils.xor(C.C3_m, Arrays.copyOfRange(C3_hash, 0, C.C3_m.length));
        byte[] r_decrypt = utils.ByteArrayUtils.xor(C.C3_r,
                Arrays.copyOfRange(C3_hash, C.C3_m.length, C.C3_m.length + C.C3_r.length));
        Element r_de = ParamsA.Zr.newElementFromBytes(r_decrypt);
        Element m_de_elem = ParamsA.G1.newElementFromHash(m_decrypt, 0, m_decrypt.length).getImmutable();
        Element C2_de = C.C1.powZn(ppkp.sk_x);
        C2_de = ParamsA.G1.newElementFromHash(C2_de.toBytes(), 0, C2_de.toBytes().length);
        C2_de = m_de_elem.powZn(r_de).mul(C2_de);
        if (C.C1.isEqual(ParamsA.g.powZn(r_de)) && C.C2.isEqual(C2_de)) {
            return true;
        }
        return false;
    }
}

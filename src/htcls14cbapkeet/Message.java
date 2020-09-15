package htcls14cbapkeet;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;
import utils.ByteArrayUtils;
import utils.HashUtils;

/*
 * 明文
 */
public class Message {
    public String m;
    public byte[] mByte;

    Message(String m) {
        this.m = m;
        this.mByte = m.getBytes();
    }

    public boolean isDecrypt(Ciphertext C, PublicPrivateKeyPair ppkp) {
        byte[] C2_hash = HashUtils.notSafeHash(C.C3_m.length + C.C3_r.length + C.C3_hm.length,
                C.C1.powZn(ppkp.sk_x).toString());

        byte[] m_de = ByteArrayUtils.xor(C.C3_m, Arrays.copyOfRange(C2_hash, 0, C.C3_m.length));
        byte[] r_de = ByteArrayUtils.xor(C.C3_r,
                Arrays.copyOfRange(C2_hash, C.C3_m.length, C.C3_m.length + C.C3_r.length));
        byte[] hm_de = ByteArrayUtils.xor(C.C3_hm, Arrays.copyOfRange(C2_hash, C.C3_m.length + C.C3_r.length,
                C.C3_m.length + C.C3_r.length + C.C3_hm.length));
        byte[] mrhm = (new String(m_de) + ParamsA.Zr.newElementFromBytes(r_de).toString() + hm_de).getBytes();
        Element u_de = ParamsA.Zr.newElementFromHash(mrhm, 0, mrhm.length).getImmutable();
        if (Arrays.equals(hm_de, HashUtils.notSafeHash(32, new String(m_de))) && C.C1.isEqual(ParamsA.g.powZn(u_de))) {
            return true;
        }
        return false;
    }
}

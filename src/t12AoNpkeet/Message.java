package t12AoNpkeet;

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
        this.mElement = ParamsA.Zr.newElementFromHash(mByte, 0, mByte.length).getImmutable();
    }

    public boolean isDecrypt(Ciphertext C, PublicPrivateKeyPair ppkp) {
        byte[] C3_hash = utils.HashUtils.notSafeHash(C.C3_m.length + C.C3_u.length, C.C1.powZn(ppkp.sk_x).toString());
        byte[] m_decrypt = utils.ByteArrayUtils.xor(C.C3_m, Arrays.copyOfRange(C3_hash, 0, C.C3_m.length));
        byte[] u_decrypt = utils.ByteArrayUtils.xor(C.C3_u,
                Arrays.copyOfRange(C3_hash, C.C3_m.length, C.C3_m.length + C.C3_u.length));
        Element u = ParamsA.Zr.newElementFromBytes(u_decrypt);
        if (ParamsA.g.powZn(u).isEqual(C.C1)
                && Arrays.equals(C.C5, utils.HashUtils.notSafeHash(32, C.C1.toString(), C.C2.toString(),
                        C.C3_m.toString(), C.C3_u.toString(), C.C4.toString(), new String(m_decrypt), u.toString()))) {
            return true;
        }
        return false;
    }
}

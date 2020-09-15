package xwzclf17vpkeet;

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
        String pk_x_r = C.C1.powZn(ppkp.sk_x).toString();
        byte[] C3_hash = utils.HashUtils.notSafeHash(C.C3_m.length + C.C3_r1.length, pk_x_r);
        byte[] m_decrypt = utils.ByteArrayUtils.xor(C.C3_m, Arrays.copyOfRange(C3_hash, 0, C.C3_m.length));
        byte[] r1_decrypt = utils.ByteArrayUtils.xor(C.C3_r1,
                Arrays.copyOfRange(C3_hash, C.C3_m.length, C.C3_m.length + C.C3_r1.length));
        Element _r1 = ParamsA.Zr.newElementFromBytes(r1_decrypt);
        if (C.C1.isEqual(ParamsA.g2.powZn(_r1)) && Arrays.equals(C.C5,
                utils.HashUtils.notSafeHash(32, C.C1.toString(), C.C2.toString(), C.C3_m.toString(), C.C3_r1.toString(),
                        C.C4.toString(), new String(m_decrypt), _r1.toString()))) {
            return true;
        }
        return false;
    }
}

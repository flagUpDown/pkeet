package m15ibeet;

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
        byte[] C5_hash = utils.HashUtils.notSafeHash(C.C5_m.length + C.C5_r1.length,
                ParamsA.pairing.pairing(ppkp.sk_y, C.C4).toString());
        byte[] m_decrypt = utils.ByteArrayUtils.xor(C.C5_m, Arrays.copyOfRange(C5_hash, 0, C.C5_m.length));
        byte[] r_decrypt = utils.ByteArrayUtils.xor(C.C5_r1,
                Arrays.copyOfRange(C5_hash, C.C5_m.length, C.C5_m.length + C.C5_r1.length));
        Element r1_de = ParamsA.Zr.newElementFromBytes(r_decrypt);
        Element m_de_elem = ParamsA.G1.newElementFromHash(m_decrypt, 0, m_decrypt.length).getImmutable();
        byte[] U1_r2 = ParamsA.pairing.pairing(ppkp.sk_x, C.C2).toBytes();
        if (C.C1.isEqual(ParamsA.g.powZn(r1_de))
                && C.C3.div(m_de_elem.powZn(r1_de)).isEqual(ParamsA.G1.newElementFromHash(U1_r2, 0, U1_r2.length))) {
            return true;
        }
        return false;
    }
}

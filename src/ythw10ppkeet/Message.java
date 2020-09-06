package ythw10ppkeet;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 明文
 * m || r <-- H(U, V, U^x) \xor W
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
        byte[] W_hash = utils.HashUtils.notSafeHash(this.mByte.length + C.W_r.length, C.U.toString(), C.V.toString(),
                C.U.powZn(ppkp.sk).toString());
        byte[] m_decrypt = utils.ByteArrayUtils.xor(C.W_m, Arrays.copyOfRange(W_hash, 0, C.W_m.length));
        byte[] r_decrypt = utils.ByteArrayUtils.xor(C.W_r,
                Arrays.copyOfRange(W_hash, C.W_m.length, C.W_m.length + C.W_r.length));
        Element r = ParamsA.Zr.newElementFromBytes(r_decrypt);
        if (Arrays.equals(m_decrypt, this.mByte) && ParamsA.g.powZn(r).isEqual(C.U)
                && this.mElement.powZn(r).isEqual(C.V)) {
            return true;
        }
        return false;
    }
}

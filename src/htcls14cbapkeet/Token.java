package htcls14cbapkeet;

import java.util.Arrays;

import utils.HashUtils;

// 用户创建Token的过程就是授权的过程
public class Token {
    public byte[] t;

    Token(Ciphertext C, PublicPrivateKeyPair ppkp) {
        byte[] C2_hash = HashUtils.notSafeHash(C.C3_m.length + C.C3_r.length + C.C3_hm.length,
                C.C1.powZn(ppkp.sk_x).toString());
        this.t = Arrays.copyOfRange(C2_hash, C.C3_m.length + C.C3_r.length,
                C.C3_m.length + C.C3_r.length + C.C3_hm.length);
    }
}

package mhzy15pkeetfa;

import java.util.Arrays;

/*
 * Type-2的Token
 * 用户创建Token的过程就是授权的过程
 */
public class Token2 {
    public byte[] t1;

    Token2(Ciphertext C, PublicPrivateKeyPair ppkp) {
        byte[] C3_hash = utils.HashUtils.notSafeHash(C.C3_mr.length + C.C3_myr.length,
                C.C2.powZn(ppkp.sk_x).toString());
        this.t1 = Arrays.copyOfRange(C3_hash, 0, C.C3_mr.length);
    }
}

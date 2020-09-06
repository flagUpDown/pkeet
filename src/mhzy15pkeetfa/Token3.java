package mhzy15pkeetfa;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * Type-3的Token
 * 用户创建Token的过程就是授权的过程
 */
public class Token3 {
    public byte[] t1;
    public Element t2;

    Token3(Ciphertext Ci, Ciphertext Cj, PublicPrivateKeyPair ppkp) {
        byte[] C3_hash = utils.HashUtils.notSafeHash(Ci.C3_mr.length + Ci.C3_myr.length,
                Ci.C2.powZn(ppkp.sk_x).toString());
        this.t1 = Arrays.copyOfRange(C3_hash, Ci.C3_mr.length, Ci.C3_mr.length + Ci.C3_myr.length);

        this.t2 = ParamsA.pairing.pairing(Ci.C1, Cj.C1).powZn(ppkp.sk_y);
    }
}

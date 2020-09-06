package mhzy15pkeetfa;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/*
 * 
 */
public class EqualityTest {
    /*
     * Type-1授权中的等值测试 Type-1: 用户1的所有密文可以与其他用户的所有密文进行等值测试
     */
    public static boolean test1(Token1 ti, Ciphertext Ci, Token1 tj, Ciphertext Cj) {
        byte[] Ci_3_hash = utils.HashUtils.notSafeHash(Ci.C3_mr.length + Ci.C3_myr.length,
                Ci.C2.powZn(ti.t1).toString());
        byte[] mr_i = utils.ByteArrayUtils.xor(Ci.C3_mr, Arrays.copyOfRange(Ci_3_hash, 0, Ci.C3_mr.length));
        Element mr_i_elem = ParamsA.G1.newElementFromBytes(mr_i);

        byte[] Cj_3_hash = utils.HashUtils.notSafeHash(Cj.C3_mr.length + Cj.C3_myr.length,
                Cj.C2.powZn(tj.t1).toString());
        byte[] mr_j = utils.ByteArrayUtils.xor(Cj.C3_mr, Arrays.copyOfRange(Cj_3_hash, 0, Cj.C3_mr.length));
        Element mr_j_elem = ParamsA.G1.newElementFromBytes(mr_j);

        Element e_1 = ParamsA.pairing.pairing(Ci.C1, mr_j_elem);
        Element e_2 = ParamsA.pairing.pairing(Cj.C1, mr_i_elem);

        if (e_1.isEqual(e_2)) {
            return true;
        } else {
            return false;
        }
    }

    /*
     * Type-2授权中的等值测试 Type-2: 用户1的指定密文可以与其他用户的指定密文进行等值测试
     */
    public static boolean test2(Token2 ti, Ciphertext Ci, Token2 tj, Ciphertext Cj) {
        byte[] mr_i = utils.ByteArrayUtils.xor(Ci.C3_mr, ti.t1);
        Element mr_i_elem = ParamsA.G1.newElementFromBytes(mr_i);

        byte[] mr_j = utils.ByteArrayUtils.xor(Cj.C3_mr, tj.t1);
        Element mr_j_elem = ParamsA.G1.newElementFromBytes(mr_j);

        Element e_1 = ParamsA.pairing.pairing(Ci.C1, mr_j_elem);
        Element e_2 = ParamsA.pairing.pairing(Cj.C1, mr_i_elem);

        if (e_1.isEqual(e_2)) {
            return true;
        } else {
            return false;
        }
    }

    /*
     * Type-3授权中的等值测试 Type-3: 用户1的指定密文可以与指定用户的指定密文进行等值测试
     */
    public static boolean test3(Token3 ti, Ciphertext Ci, Token3 tj, Ciphertext Cj) {
        byte[] myr_i = utils.ByteArrayUtils.xor(Ci.C3_myr, ti.t1);
        Element myr_i_elem = ParamsA.G1.newElementFromBytes(myr_i);

        byte[] myr_j = utils.ByteArrayUtils.xor(Cj.C3_myr, tj.t1);
        Element myr_j_elem = ParamsA.G1.newElementFromBytes(myr_j);

        Element e_1 = ParamsA.pairing.pairing(Ci.C1, myr_j_elem);
        e_1 = e_1.div(ParamsA.pairing.pairing(Cj.C1, myr_i_elem));

        Element e_2 = tj.t2.div(ti.t2);

        if (e_1.isEqual(e_2)) {
            return true;
        } else {
            return false;
        }
    }

    /*
     * Type-4授权中的等值测试 Type-4: 用户1的指定密文可以与其他用户的其他密文进行等值测试
     */
    public static boolean test4(Token2 ti, Ciphertext Ci, Token1 tj, Ciphertext Cj) {
        byte[] mr_i = utils.ByteArrayUtils.xor(Ci.C3_mr, ti.t1);
        Element mr_i_elem = ParamsA.G1.newElementFromBytes(mr_i);

        byte[] Cj_3_hash = utils.HashUtils.notSafeHash(Cj.C3_mr.length + Cj.C3_myr.length,
                Cj.C2.powZn(tj.t1).toString());
        byte[] mr_j = utils.ByteArrayUtils.xor(Cj.C3_mr, Arrays.copyOfRange(Cj_3_hash, 0, Cj.C3_mr.length));
        Element mr_j_elem = ParamsA.G1.newElementFromBytes(mr_j);

        Element e_1 = ParamsA.pairing.pairing(Ci.C1, mr_j_elem);
        Element e_2 = ParamsA.pairing.pairing(Cj.C1, mr_i_elem);

        if (e_1.isEqual(e_2)) {
            return true;
        } else {
            return false;
        }
    }
}

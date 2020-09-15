package xwzclf17vpkeet;

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
        Element e_1 = Ci.C4.div(Ci.C2.powZn(ti.t1));
        Element e_2 = Cj.C4.div(Cj.C2.powZn(tj.t1));

        if (e_1.isEqual(e_2)) {
            return true;
        } else {
            return false;
        }
    }

    /*
     * Type-2授权中的等值测试 Type-2: 用户1的所有密文可以与指定用户的所有密文进行等值测试
     */
    public static boolean test2(Token2 ti, Ciphertext Ci, Token2 tj, Ciphertext Cj) {
        Element e_1 = ParamsA.pairing.pairing(Ci.C4, ti.t1);
        e_1 = e_1.div(ParamsA.pairing.pairing(Ci.C2, ti.t2));

        Element e_2 = ParamsA.pairing.pairing(Cj.C4, tj.t1);
        e_2 = e_2.div(ParamsA.pairing.pairing(Cj.C2, tj.t2));

        if (e_1.isEqual(e_2)) {
            return true;
        } else {
            return false;
        }
    }

    /*
     * Type-3授权中的等值测试 Type-3: 用户1的指定密文可以与指定用户的所有密文进行等值测试
     */
    public static boolean test3(Token3 ti, Ciphertext Ci, Token2 tj, Ciphertext Cj) {
        Element e_1 = ParamsA.pairing.pairing(Ci.C4, ti.t2);
        e_1 = e_1.mul(ParamsA.pairing.pairing(ti.Yj, ti.t3));
        e_1 = e_1.div(ParamsA.pairing.pairing(ti.t1, ti.t2));

        Element e_2 = ParamsA.pairing.pairing(Cj.C4, tj.t1);
        e_2 = e_2.div(ParamsA.pairing.pairing(Cj.C2, tj.t2));

        if (e_1.isEqual(e_2)) {
            return true;
        } else {
            return false;
        }
    }
}

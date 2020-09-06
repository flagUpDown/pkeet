package params;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/*
 * 使用pkeet/params/a.properties文件, 设置参数
 * Zr是模r的整数环
 * G1,GT为素数阶r的乘法群
 * 映射关系 e: G1 * G1 ---> GT
 * g是G1中的一个生成元
 */
public class ParamsA {
    public static Pairing pairing = PairingFactory.getPairing("params/a.properties");;
    public static Field<?> Zr = pairing.getZr();
    public static Field<?> G1 = pairing.getG1();
    public static Field<?> G2 = pairing.getG2();
    public static Field<?> GT = pairing.getGT();
    public static Element g = ParamsA.G1.newRandomElement().getImmutable();
    public static Element g2 = ParamsA.G2.newRandomElement().getImmutable();
}

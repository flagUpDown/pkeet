package t12fgpkeet;

import it.unisa.dia.gas.jpbc.Element;
import params.ParamsA;

/* Token是由两个代理服务器(Vx,Vy)共同进行生成
 * 用户创建Token的过程就是授权的过程
 */
public class Token {
    // Vx = (g2^r, g2^{(y1-t1)*r}, g2^{t2*r})
    public Proxy Vx;
    // Vy = (g2^r, g2^{t1*r}, g2^{(y2-t2)*r})
    public Proxy Vy;

    Token(PublicPrivateKeyPair ppkp_1, PublicPrivateKeyPair ppkp_2, Element r) {
        Vx = new Proxy();
        Vy = new Proxy();

        // 用户1随机生成t1 \in Zr
        Element t1 = ParamsA.Zr.newRandomElement().getImmutable();
        // 用户2随机生成t2 \in Zr
        Element t2 = ParamsA.Zr.newRandomElement().getImmutable();

        Vx.v1 = ParamsA.g2.powZn(r);
        Vx.v2 = ParamsA.g2.powZn(ppkp_1.sk_y.sub(t1).mul(r));
        Vx.v3 = ParamsA.g2.powZn(t2.mul(r));

        Vy.v1 = Vx.v1.duplicate();
        Vy.v2 = ParamsA.g2.powZn(t1.mul(r));
        Vy.v3 = ParamsA.g2.powZn(ppkp_2.sk_y.sub(t2).mul(r));
    }

}

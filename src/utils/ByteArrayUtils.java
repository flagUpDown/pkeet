package utils;

public class ByteArrayUtils {
    static public byte[] xor(byte[] b1, byte[] b2) {
        if (b1.length != b2.length) {
            // TODO 抛出一个异常
            System.out.println("两个byte数组长度不相同");
        }
        byte[] result = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            result[i] = (byte) (b1[i] ^ b2[i]);
        }
        return result;
    }
}

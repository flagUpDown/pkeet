package utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtils {
    // 输入特定的字符串, 输出k比特的hash值
    static public byte[] notSafeHash(int k, String str, String... strs) {
        byte[] result = new byte[k];
        byte[] curr;
        str = str + String.join("", strs);
        int len = str.length();
        int n = k / 32;
        int block = len / (n + 1);
        int start = 0;
        int end = start + block;
        MessageDigest messageDigest = null;
        for (int i = 0; i < n; i++) {
            try {
                messageDigest = MessageDigest.getInstance("SHA-256");
                messageDigest.update(str.substring(start, end).getBytes());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            curr = messageDigest.digest();

            System.arraycopy(curr, 0, result, 32 * i, curr.length);
            start = end;
            end = start + block;
        }
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.substring(start).getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        curr = messageDigest.digest();
        System.arraycopy(curr, 0, result, 32 * n, k % 32);
        return result;
    }
}

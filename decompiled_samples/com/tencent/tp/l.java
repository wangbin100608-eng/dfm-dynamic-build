package com.tencent.tp;

/* JADX INFO: loaded from: classes2.dex */
public class l {
    public static char a(char c4) {
        char c5;
        if (c4 >= 'a' && c4 <= 'z') {
            c5 = (char) (c4 + 5);
            if (c5 <= 'z') {
                return c5;
            }
        } else {
            if (c4 < 'A' || c4 > 'Z') {
                return c4;
            }
            c5 = (char) (c4 + 5);
            if (c5 <= 'Z') {
                return c5;
            }
        }
        return (char) (c5 - 26);
    }

    public static String a(String str) {
        if (str == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i4 = 0; i4 < str.length(); i4++) {
            sb.append(a(str.charAt(i4)));
        }
        return sb.toString();
    }
}

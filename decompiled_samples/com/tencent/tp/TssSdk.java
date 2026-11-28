package com.tencent.tp;

import android.content.Context;

/* JADX INFO: loaded from: classes2.dex */
public class TssSdk {
    public static final int ACE_LOCALE_CN = 1;
    public static final int ACE_LOCALE_EN = 2;
    public static final int ACE_LOCALE_EU = 5;
    public static final int ACE_LOCALE_IN = 6;
    public static final int ACE_LOCALE_JP = 7;
    public static final int ACE_LOCALE_KR = 8;
    public static final int ACE_LOCALE_RU = 3;
    public static final int ACE_LOCALE_TW = 9;
    public static final int ACE_LOCALE_US = 4;
    public static final int ACE_LOCALE_VN = 10;
    public static final int ACE_LOCAL_GLOBAL = 998;
    public static final int ACE_LOCAL_OTHERS = 999;
    public static final int APP_OBJECT_ACTIVITY = 1;
    public static final int APP_OBJECT_CONTEXT = 2;
    public static final int ENTRT_ID_FACEBOOK = 3;
    public static final int ENTRY_ID_APPLE = 11;
    public static final int ENTRY_ID_CUSTOM = 21;
    public static final int ENTRY_ID_EA = 20;
    public static final int ENTRY_ID_EMAIL = 131;
    public static final int ENTRY_ID_GAMECENTER = 7;
    public static final int ENTRY_ID_GARENA = 14;
    public static final int ENTRY_ID_GOOGLEPLAY = 8;
    public static final int ENTRY_ID_HW = 15;
    public static final int ENTRY_ID_KUAISHOU = 10;
    public static final int ENTRY_ID_LINE = 5;
    public static final int ENTRY_ID_MICROSOFT = 19;
    public static final int ENTRY_ID_MM = 2;
    public static final int ENTRY_ID_NAVER = 13;
    public static final int ENTRY_ID_NEXON = 12;
    public static final int ENTRY_ID_NINTENDO = 17;
    public static final int ENTRY_ID_OTHERS = 99;
    public static final int ENTRY_ID_PSN = 18;
    public static final int ENTRY_ID_QQ = 1;
    public static final int ENTRY_ID_RIOT = 16;
    public static final int ENTRY_ID_TWITTER = 4;
    public static final int ENTRY_ID_VK = 9;
    public static final int ENTRY_ID_WHATSAPP = 6;
    public static final String TSS_SDK_VERSION = "8.0.46(2020/11/10)-jar-version";

    public interface ISendDataToSvr {
        int sendDataToSvr(byte[] bArr, int i4);
    }

    static {
        System.loadLibrary("tersafe");
    }

    public static String decTssInfo(String str) {
        return ioctl(String.format("dec_tss_info:%s", str));
    }

    public static void enableGameReport() {
        ioctl("EnableGameReport");
    }

    public static byte[] getReportData() {
        TssIOCtlResult tssIOCtlResult = new TssIOCtlResult();
        tssIOCtlResult.cmd = l.a("bzo_mzkjmo_yvov");
        if (getsdkantidata(tssIOCtlResult) != 0) {
            return null;
        }
        return tssIOCtlResult.data;
    }

    public static native int getsdkantidata(TssIOCtlResult tssIOCtlResult);

    public static native int hasMatchRate(int i4);

    public static void init(Context context, int i4) {
        TssSdkInitInfo tssSdkInitInfo = new TssSdkInitInfo();
        tssSdkInitInfo.game_id = i4;
        init(tssSdkInitInfo);
    }

    public static native void init(TssSdkInitInfo tssSdkInitInfo);

    public static void initEx(int i4, String str) {
        m.a(l.a("vkk_fzt:") + str);
        TssSdkInitInfo tssSdkInitInfo = new TssSdkInitInfo();
        tssSdkInitInfo.game_id = i4;
        init(tssSdkInitInfo);
    }

    public static String ioctl(String str) {
        if (str == null || str.length() == 0) {
            return null;
        }
        TssIOCtlResult tssIOCtlResult = new TssIOCtlResult();
        tssIOCtlResult.cmd = str;
        if (getsdkantidata(tssIOCtlResult) != 0) {
            return null;
        }
        return tssIOCtlResult.response;
    }

    public static void onPause() {
        TssSdkGameStatusInfo tssSdkGameStatusInfo = new TssSdkGameStatusInfo();
        tssSdkGameStatusInfo.game_status = 2;
        setgamestatus(tssSdkGameStatusInfo);
    }

    public static void onRecvData(byte[] bArr) {
        senddatatosdk(bArr, bArr.length);
    }

    public static void onResume() {
        TssSdkGameStatusInfo tssSdkGameStatusInfo = new TssSdkGameStatusInfo();
        tssSdkGameStatusInfo.game_status = 1;
        setgamestatus(tssSdkGameStatusInfo);
    }

    public static native void onruntimeinfo(byte[] bArr, int i4);

    public static void registTssInfoReceiver(TssInfoPublisher.TssInfoReceiver tssInfoReceiver) {
        TssInfoPublisher.a().a(tssInfoReceiver);
    }

    public static native void senddatatosdk(byte[] bArr, int i4);

    public static native void senddatatosvr(byte[] bArr, int i4);

    public static void setAppObject(int i4, Object obj) {
        n.a(i4, obj);
        setappobject(i4, obj);
    }

    public static void setLocaleId(int i4) {
        ioctl("SetLocaleId:" + i4);
    }

    public static void setUserInfo(int i4, String str) {
        TssSdkUserInfo tssSdkUserInfo = new TssSdkUserInfo();
        tssSdkUserInfo.entry_id = i4;
        tssSdkUserInfo.uin_type = 2;
        tssSdkUserInfo.uin_str = str;
        tssSdkUserInfo.app_id_type = 2;
        tssSdkUserInfo.app_id_str = "";
        setuserinfo(tssSdkUserInfo);
    }

    public static native int setappobject(int i4, Object obj);

    public static native void setgamestatus(TssSdkGameStatusInfo tssSdkGameStatusInfo);

    public static native void setsenddatatosvrcb(Object obj);

    public static native void setuserinfo(TssSdkUserInfo tssSdkUserInfo);

    public static native void setuserinfoex(TssSdkUserInfoEx tssSdkUserInfoEx);
}

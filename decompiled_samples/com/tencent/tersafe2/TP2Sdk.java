package com.tencent.tersafe2;

import com.tencent.tp.TssIOCtlResult;
import com.tencent.tp.TssInfoPublisher;
import com.tencent.tp.TssSdk;
import com.tencent.tp.TssSdkGameStatusInfo;
import com.tencent.tp.TssSdkInitInfo;
import com.tencent.tp.TssSdkUserInfoEx;
import com.tencent.tp.l;
import com.tencent.tp.m;

/* JADX INFO: loaded from: classes2.dex */
public class TP2Sdk {
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

    public static String decTssInfo(String str) {
        return TssSdk.decTssInfo(str);
    }

    public static void enableGameChannel() {
        ioctl("EnableGameReport");
    }

    public static byte[] getReportData() {
        TssIOCtlResult tssIOCtlResult = new TssIOCtlResult();
        tssIOCtlResult.cmd = l.a("bzo_mzkjmo_yvov");
        if (TssSdk.getsdkantidata(tssIOCtlResult) != 0) {
            return null;
        }
        return tssIOCtlResult.data;
    }

    public static byte[] getReportData2() {
        TssIOCtlResult tssIOCtlResult = new TssIOCtlResult();
        tssIOCtlResult.cmd = "";
        if (TssSdk.getsdkantidata(tssIOCtlResult) != 0) {
            return null;
        }
        return tssIOCtlResult.data;
    }

    public static int init(int i4) {
        TssSdkInitInfo tssSdkInitInfo = new TssSdkInitInfo();
        tssSdkInitInfo.game_id = i4;
        TssSdk.init(tssSdkInitInfo);
        return 0;
    }

    public static int initEx(int i4, String str) {
        m.a(l.a("vkk_fzt:") + str);
        return init(i4);
    }

    public static String ioctl(String str) {
        return TssSdk.ioctl(str);
    }

    public static int onAppPause() {
        TssSdkGameStatusInfo tssSdkGameStatusInfo = new TssSdkGameStatusInfo();
        tssSdkGameStatusInfo.game_status = 2;
        TssSdk.setgamestatus(tssSdkGameStatusInfo);
        return 0;
    }

    public static int onAppResume() {
        TssSdkGameStatusInfo tssSdkGameStatusInfo = new TssSdkGameStatusInfo();
        tssSdkGameStatusInfo.game_status = 1;
        TssSdk.setgamestatus(tssSdkGameStatusInfo);
        return 0;
    }

    public static int onUserLogin(int i4, int i5, String str, String str2) {
        TssSdkUserInfoEx tssSdkUserInfoEx = new TssSdkUserInfoEx();
        tssSdkUserInfoEx.entry_id = i4;
        tssSdkUserInfoEx.uin_type = 2;
        tssSdkUserInfoEx.uin_int = 0;
        tssSdkUserInfoEx.uin_str = str;
        tssSdkUserInfoEx.app_id_type = 2;
        tssSdkUserInfoEx.app_id_int = 0;
        tssSdkUserInfoEx.app_id_str = "";
        tssSdkUserInfoEx.world_id = i5;
        tssSdkUserInfoEx.role_id = str2;
        TssSdk.setuserinfoex(tssSdkUserInfoEx);
        return 0;
    }

    public static void registTssInfoReceiver(TssInfoPublisher.TssInfoReceiver tssInfoReceiver) {
        TssSdk.registTssInfoReceiver(tssInfoReceiver);
    }

    public static void setAppObject(int i4, Object obj) {
        TssSdk.setAppObject(i4, obj);
    }

    public static void setLocaleId(int i4) {
        ioctl("SetLocaleId:" + i4);
    }

    public static int setPopupOptions(int i4) {
        return -1;
    }
}

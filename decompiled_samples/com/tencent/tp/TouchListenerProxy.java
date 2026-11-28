package com.tencent.tp;

import android.content.Context;
import android.util.DisplayMetrics;
import android.view.InputDevice;
import android.view.MotionEvent;
import android.view.View;
import com.tencent.gcloud.gpm.utils.AttachmentUtil;
import java.util.Locale;

/* JADX INFO: loaded from: classes2.dex */
public class TouchListenerProxy implements View.OnTouchListener {
    private static volatile TouchListenerProxy mInstance;
    private int mOnTouchCnt;
    private boolean mOntouchRetVal = false;
    private View.OnTouchListener mRawListener;
    private int mScreenHeight;
    private int mScreenWidth;

    private TouchListenerProxy() {
    }

    public static TouchListenerProxy getInstance() {
        if (mInstance == null) {
            synchronized (TouchListenerProxy.class) {
                try {
                    if (mInstance == null) {
                        mInstance = new TouchListenerProxy();
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        return mInstance;
    }

    private void log(String str) {
        try {
            byte[] bytes = ("*#06#:" + str).getBytes(AttachmentUtil.UTF_8);
            TssSdk.onruntimeinfo(bytes, bytes.length);
        } catch (Exception unused) {
        }
    }

    private void notifyEventToAno(MotionEvent motionEvent) {
        TssSdk.ioctl(String.format(Locale.ENGLISH, l.a("VyyVijOjpxcZqzio:dy=%y|zo=%y|yo=%y|hd=%.1a|hv=%.1a"), Integer.valueOf(motionEvent.getPointerId(motionEvent.getActionIndex())), Long.valueOf(motionEvent.getDownTime()), Long.valueOf(motionEvent.getEventTime()), Float.valueOf(motionEvent.getTouchMinor()), Float.valueOf(motionEvent.getTouchMajor())));
    }

    private void notifyMotionEvent(MotionEvent motionEvent) {
        int i4;
        String str;
        if (motionEvent == null) {
            return;
        }
        if (this.mScreenWidth == 0 || this.mScreenHeight == 0) {
            Context contextB = n.b();
            if (contextB == null) {
                return;
            }
            try {
                DisplayMetrics displayMetrics = contextB.getResources().getDisplayMetrics();
                this.mScreenWidth = displayMetrics.widthPixels;
                this.mScreenHeight = displayMetrics.heightPixels;
            } catch (Throwable unused) {
                this.mScreenWidth = 1;
                this.mScreenHeight = 1;
            }
        }
        int i5 = this.mScreenWidth;
        if (i5 < 2 || (i4 = this.mScreenHeight) < 2) {
            return;
        }
        int deviceId = motionEvent.getDeviceId();
        InputDevice device = motionEvent.getDevice();
        String name = device == null ? "unavailable" : device.getName();
        int source = motionEvent.getSource();
        int flags = motionEvent.getFlags();
        long downTime = motionEvent.getDownTime();
        long eventTime = motionEvent.getEventTime();
        int actionMasked = motionEvent.getActionMasked();
        String str2 = "AddTouchEvent:col=%d|row=%d|col_max=%d|row_max=%d|id=%d|name=%s|source=%d|external=%d|flags=%d|action=%d|index=%d|et=%d|dt=%d";
        if (actionMasked == 2) {
            int pointerCount = motionEvent.getPointerCount();
            str = "";
            int i6 = 0;
            while (i6 < pointerCount) {
                String str3 = str2;
                str = String.format(Locale.ENGLISH, str3, Integer.valueOf((int) motionEvent.getX(i6)), Integer.valueOf((int) motionEvent.getY(i6)), Integer.valueOf(i5), Integer.valueOf(i4), Integer.valueOf(deviceId), name, Integer.valueOf(source), 0, Integer.valueOf(flags), Integer.valueOf(actionMasked), Integer.valueOf(i6), Long.valueOf(eventTime), Long.valueOf(downTime));
                TssSdk.ioctl(str);
                i6++;
                str2 = str3;
                pointerCount = pointerCount;
                actionMasked = actionMasked;
            }
        } else {
            int actionIndex = motionEvent.getActionIndex();
            str = String.format(Locale.ENGLISH, "AddTouchEvent:col=%d|row=%d|col_max=%d|row_max=%d|id=%d|name=%s|source=%d|external=%d|flags=%d|action=%d|index=%d|et=%d|dt=%d", Integer.valueOf((int) motionEvent.getX(actionIndex)), Integer.valueOf((int) motionEvent.getY(actionIndex)), Integer.valueOf(i5), Integer.valueOf(i4), Integer.valueOf(deviceId), name, Integer.valueOf(source), 0, Integer.valueOf(flags), Integer.valueOf(actionMasked), Integer.valueOf(actionIndex), Long.valueOf(eventTime), Long.valueOf(downTime));
            TssSdk.ioctl(str);
        }
        int i7 = this.mOnTouchCnt;
        this.mOnTouchCnt = i7 + 1;
        if (i7 < 4) {
            log(str);
        }
    }

    @Override // android.view.View.OnTouchListener
    public boolean onTouch(View view, MotionEvent motionEvent) {
        if (motionEvent != null) {
            int actionMasked = motionEvent.getActionMasked();
            if (actionMasked == 0 || actionMasked == 1 || actionMasked == 2 || actionMasked == 5 || actionMasked == 6) {
                notifyMotionEvent(motionEvent);
            }
            if (motionEvent.getActionMasked() == 6 || motionEvent.getActionMasked() == 1) {
                notifyEventToAno(motionEvent);
            }
        }
        View.OnTouchListener onTouchListener = this.mRawListener;
        return onTouchListener != null ? onTouchListener.onTouch(view, motionEvent) : this.mOntouchRetVal;
    }

    public void setOntouchRetVal(boolean z3) {
        this.mOntouchRetVal = z3;
    }

    public void setRawListener(View.OnTouchListener onTouchListener) {
        this.mRawListener = onTouchListener;
    }
}

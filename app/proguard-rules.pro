# ═══ wy-app 混淆保留规则 ═══

# JS 桥接契约:页面 JS 通过 window.AndroidBridge.<方法名>() 调用,
# @JavascriptInterface 标注的方法名不可混淆,否则桥接断裂
-keepattributes *Annotation*
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# Chaquopy SDK:内部大量 JNI/反射,整体保留
-keep class com.chaquo.python.** { *; }
-dontwarn com.chaquo.python.**

# AndroidManifest 引用的组件(Activity)由 AGP 自动保留,无需手动声明

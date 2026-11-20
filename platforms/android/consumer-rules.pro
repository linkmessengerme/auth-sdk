# UniFFI/JNA use reflective FFI interfaces and structure field names.
-keep class me.linkmessenger.auth.generated.** { *; }
-keep class com.sun.jna.** { *; }
-keep interface com.sun.jna.** { *; }

# JNA's optional desktop AWT helpers are unreachable on Android.
# https://github.com/java-native-access/jna/blob/5.17.0/www/FrequentlyAskedQuestions.md#jna-on-android
-dontwarn java.awt.Component
-dontwarn java.awt.GraphicsEnvironment
-dontwarn java.awt.HeadlessException
-dontwarn java.awt.Window

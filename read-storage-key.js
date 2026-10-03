// SmartThings 1.8.51.30 (185130010), ARM64. Run only through the host helper.
// The RECOVERY_KEY message is SECRET. Never log this agent's raw output.
// Read only the existing IoTivity storage key. Never generate or replace a key.
Java.perform(function () {
  try {
    const context = Java.use("android.app.ActivityThread").currentApplication();
    const info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
    if (Process.arch !== "arm64" || info.versionName.value !== "1.8.51.30" ||
        info.versionCode.value !== 185130010) {
      throw new Error("Unsupported app build or architecture");
    }
    const component = Java.cast(Java.use("sk.b").a(context),
      Java.use("com.samsung.android.oneconnect.f4"));
    const manager = component.X();
    if (manager.b.value === null) throw new Error("Existing wrapping key is not loaded");
    const wrapped = context.getSharedPreferences("iotivityKey", 0)
      .getString("iotivityKey", null);
    if (wrapped === null || !wrapped.startsWith(":v1:"))
      throw new Error("Missing or unsupported existing IoTivity key");
    const encoded = manager.a.overload("java.lang.String").call(manager, wrapped);
    const bytes = Java.use("android.util.Base64").decode(encoded, 0);
    if (bytes.length !== 32) throw new Error("Unexpected IoTivity key length");
    console.log("RECOVERY_KEY:" + Java.use("android.util.Base64").encodeToString(bytes, 2));
  } catch (_) {
    // Do not include arbitrary Java exceptions: they could contain private data.
    console.log("RECOVERY_ERROR: existing key unavailable or unsupported app build");
  }
});

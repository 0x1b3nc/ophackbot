// Lab-only SSL unpin template for authorized mobile bounty / CTF builds.
// DO NOT use against apps without permission. Loaded only via frida_run_script + approve.
Java.perform(function () {
  try {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function () {
      console.log("[hackbot] TrustManagerImpl.verifyChain bypassed (lab)");
      return arguments[0];
    };
  } catch (e) {
    console.log("[hackbot] TrustManagerImpl hook skip: " + e);
  }
  try {
    var OkHttp = Java.use("okhttp3.CertificatePinner");
    OkHttp.check.overload("java.lang.String", "java.util.List").implementation = function () {
      console.log("[hackbot] OkHttp CertificatePinner.check bypassed (lab)");
    };
  } catch (e) {
    console.log("[hackbot] OkHttp hook skip: " + e);
  }
  console.log("[hackbot] ssl_unpin_lab loaded");
});

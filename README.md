# LAB-11-Bypass-de-la-D-tection-de-Root-Android-avec-Frida-Hooks-Java-Natif-

Étape 1 — Démarrage et repérage du package
Connecter l’appareil (USB, débogage autorisé), lancer frida-server (voir plus haut).
Lister les applications pour retrouver le package:

[Import OVA](https://github.com/user-attachments/assets/953e5a0c-862b-4321-bc4c-cadbf0809183)

---

Étape 2 — Script Frida (bypass Java) prêt à l’emploi
Créez un fichier bypass_root.js sur votre PC avec le contenu ci‑dessous.
// bypass_root.js — Neutralise des checks Java courants (Build.TAGS, File.exists, Runtime.exec, RootBeer)

function safeContains(str, needle) {
  try { return (str || "").toLowerCase().indexOf((needle||"").toLowerCase()) !== -1; } catch (_) { return false; }
}

const suspiciousPaths = [
  "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
  "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
  "/system/bin/.ext/.su", "/system/usr/we-need-root/",
  "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
  "/system/bin/busybox", "/system/xbin/busybox"
];

Java.perform(function () {
  // 1) Forcer Build.TAGS à une valeur non suspecte
  try {
    const Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'TAGS', { get: function() { return 'release-keys'; } });
    console.log('[+] Hook Build.TAGS -> release-keys');
  } catch (e) { console.log('[-] Build.TAGS hook failed:', e); }

  // 2) RootBeer (si présent)
  try {
    const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function () { console.log('[+] RootBeer.isRooted -> false'); return false; };
    if (RootBeer.isRootedWithBusyBoxCheck) {
      RootBeer.isRootedWithBusyBoxCheck.implementation = function () { console.log('[+] RootBeer.isRootedWithBusyBoxCheck -> false'); return false; };
    }
  } catch (e) { console.log('[*] RootBeer non présent ou nom différent:', e.message); }

  // 3) File.exists -> retourner false pour chemins suspects
  try {
    const File = Java.use('java.io.File');
    File.exists.implementation = function () {
      const path = this.getAbsolutePath();
      if (suspiciousPaths.indexOf(path) !== -1) {
        console.log('[+] File.exists bypass for', path);
        return false;
      }
      return this.exists.call(this);
    };
  } catch (e) { console.log('[-] File.exists hook failed:', e); }

  // 4) Runtime.exec -> bloquer su/which/busybox
  try {
    const Runtime = Java.use('java.lang.Runtime');
    const JString = Java.use('java.lang.String');
    const StringArray = Java.use('[Ljava.lang.String;');

    function blockIfSuspicious(cmdOrArr) {
      const joined = Array.isArray(cmdOrArr) ? cmdOrArr.join(' ') : ('' + cmdOrArr);
      if (safeContains(joined, ' su') || joined.trim().toLowerCase().startsWith('su') || safeContains(joined, 'which su') || safeContains(joined, 'busybox')) {
        console.log('[+] Blocked Runtime.exec:', joined);
        return ['sh', '-c', 'echo'];
      }
      return null;
    }

    // exec(String)
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      const repl = blockIfSuspicious(cmd);
      return repl ? this.exec(JString.$new(repl.join(' '))) : this.exec(cmd);
    };
    // exec(String[])
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
      const js = arr ? Array.from(arr) : [];
      const repl = blockIfSuspicious(js);
      if (repl) {
        const a = StringArray.$new(repl.length);
        for (let i = 0; i < repl.length; i++) a[i] = JString.$new(repl[i]);
        return this.exec(a);
      }
      return this.exec(arr);
    };
    // exec(String, String[])
    Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (cmd, envp) {
      const repl = blockIfSuspicious(cmd);
      return repl ? this.exec(JString.$new(repl.join(' ')), envp) : this.exec(cmd, envp);
    };
    // exec(String[], String[])
    Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (arr, envp) {
      const js = arr ? Array.from(arr) : [];
      const repl = blockIfSuspicious(js);
      if (repl) {
        const a = StringArray.$new(repl.length);
        for (let i = 0; i < repl.length; i++) a[i] = JString.$new(repl[i]);
        return this.exec(a, envp);
      }
      return this.exec(arr, envp);
    };

    console.log('[+] Hooks Runtime.exec installés');
  } catch (e) { console.log('[-] Runtime.exec hooks failed:', e); }

  console.log('[+] Java layer bypass installed');
});
Lancement:
frida -U -f com.example.rootcheck -l bypass_root.js --no-pause
Attendu: l’app démarre et les contrôles Java simples (« RootBeer simple », Build.TAGS, File.exists, Runtime.exec) ne détectent plus le root.

[Import OVA](https://github.com/user-attachments/assets/8fdb1d9e-76d4-4f42-98f7-46e5930018b3)


---

Étape 3 — Ajouter des hooks natifs (si la détection passe par du code C/C++)
Quand une app utilise le NDK pour vérifier des chemins, il faut bloquer open/openat/access/stat/lstat sur des chemins suspects, et parfois filtrer /proc/mounts.
Créez bypass_native.js:
// bypass_native.js — Neutralise open/openat/access/stat/lstat sur chemins suspects

const SUS = [
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/system/su',
  '/system/bin/busybox', '/system/xbin/busybox'
];

function isSuspiciousPath(ptrPath) {
  try { const p = ptrPath.readCString(); return !!p && (SUS.indexOf(p) !== -1 || p.indexOf('/proc/mounts') !== -1 || p.indexOf('/proc/self/mounts') !== -1); } catch (_) { return false; }
}

function hookFunc(name, argIndexForPath) {
  try {
    const addr = Module.getExportByName(null, name);
    Interceptor.attach(addr, {
      onEnter(args) {
        const pathPtr = argIndexForPath >= 0 ? args[argIndexForPath] : null;
        if (pathPtr && isSuspiciousPath(pathPtr)) {
          this.block = true;
          this.path = pathPtr.readCString();
        }
      },
      onLeave(retval) {
        if (this.block) {
          console.log('[+] Blocked', name, 'on', this.path);
          retval.replace(ptr(-1));
        }
      }
    });
    console.log('[+] Hooked', name);
  } catch (e) { /* silencieux si non dispo sur la plateforme */ }
}

hookFunc('open', 0);     // int open(const char *pathname, int flags, ...)
hookFunc('openat', 1);   // int openat(int dirfd, const char *pathname, int flags, ...)
hookFunc('access', 0);   // int access(const char *pathname, int mode)
hookFunc('stat', 0);     // int stat(const char *pathname, struct stat *buf)
hookFunc('lstat', 0);    // int lstat(const char *pathname, struct stat *buf)
Lancement combiné:
frida -U -f com.example.rootcheck -l bypass_root.js -l bypass_native.js --no-pause
Astuce: si l’app lit /proc/mounts (pour partitions RW), vous pouvez plutôt falsifier le contenu via hooks fopen/fgets/read et filtrer les lignes contenant rw,.

[Import OVA](https://github.com/user-attachments/assets/227ad6a8-10d6-456d-931f-5625b1170e71)

---

Étape 4 — Masquer quelques anti‑Frida basiques (optionnel)
Certaines apps cherchent des marqueurs « frida » ou scannent les ports.
// anti_frida.js — Masque quelques indices Frida côté Java

Java.perform(function() {
  // Masquer des variables d’environnement mentionnant FRIDA
  try {
    const Sys = Java.use('java.lang.System');
    Sys.getenv.overload('java.lang.String').implementation = function (name) {
      if (name && name.toLowerCase().indexOf('frida') !== -1) {
        console.log('[+] Hiding env var', name);
        return null;
      }
      return this.getenv(name);
    };
  } catch (e) {}

  // Bloquer connexions aux ports Frida habituels
  try {
    const InetSocketAddress = Java.use('java.net.InetSocketAddress');
    const Socket = Java.use('java.net.Socket');
    Socket.connect.overload('java.net.SocketAddress').implementation = function (addr) {
      try {
        const s = addr.toString();
        if (s.indexOf(':27042') !== -1 || s.indexOf(':27043') !== -1) {
          console.log('[+] Blocked connect to', s);
          throw new Error('Connection refused');
        }
      } catch (_) {}
      return this.connect(addr);
    };
  } catch (e) {}
});
Lancer avec:
frida -U -f com.example.rootcheck -l bypass_root.js -l bypass_native.js -l anti_frida.js --no-pause

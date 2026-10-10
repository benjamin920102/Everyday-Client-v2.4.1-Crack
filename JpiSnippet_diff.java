import java.io.*;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.function.Function;
import java.util.jar.*;
import java.util.Base64;
import org.objectweb.asm.*;
import org.objectweb.asm.Type;

public class JpiSnippet {

    static final String DEFAULT_JAR =
        "C:\\Users\\benja\\Documents\\pcl2\\.minecraft\\versions\\Everyday2.4.1\\mods\\EveryDay-v2_4_1-doubles-deobf.jar";

    static final class Entry {
        String path;          // e.g. "obf/000O0.class"
        String internalName;  // from ASM, e.g. "obf/000O0"
        int access;
        String superName;
        List<String> interfaces = new ArrayList<>();
        List<MethodInfo> methods = new ArrayList<>();
        List<FieldInfo> fields = new ArrayList<>();
        byte[] bytecode;                 // original class bytes
        String bytecodeBase64;
        byte[] patchedBytes;             // native flags stripped + stub bodies (null if none)
        String patchedBytecodeBase64;
        int nativeCount;                 // number of ACC_NATIVE methods found
        boolean patched;                 // true if patchedBytes was produced
        int size;
        String error;
    }

    static final class MethodInfo {
        String name;
        String desc;
        int access;
        boolean isNative;
    }

    static final class FieldInfo {
        String name;
        String desc;
        int access;
    }

    public static void execute(PrintStream out) {
        try {
            Path jarPath = Paths.get(System.getProperty("super.jar", DEFAULT_JAR));
            if (!Files.isRegularFile(jarPath)) {
                // try relative to current dir / common places
                Path alt = Paths.get("attachments", DEFAULT_JAR);
                if (Files.isRegularFile(alt)) jarPath = alt;
                else {
                    out.println("JAR not found: " + jarPath.toAbsolutePath());
                    out.println("Set -Dsuper.jar=/full/path/to/jar");
                    return;
                }
            }
            out.println("Target JAR: " + jarPath.toAbsolutePath());

            List<Entry> results = new ArrayList<>();
            Map<String, byte[]> patchedMap = new LinkedHashMap<>(); // path -> patched bytes
            int total = 0, ok = 0, fail = 0, filtered = 0;

            try (JarFile jar = new JarFile(jarPath.toFile())) {
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    JarEntry je = entries.nextElement();
                    String name = je.getName();
                    // only obf/ and native/ class files
                    if (!name.endsWith(".class")) continue;
                    if (!name.startsWith("obf/") && !name.startsWith("native/")) continue;

                    total++;
                    Entry e = new Entry();
                    e.path = name;
                    e.size = (int) je.getSize();

                    try (InputStream in = jar.getInputStream(je)) {
                        byte[] bytes = in.readAllBytes();
                        e.bytecode = bytes;
                        e.bytecodeBase64 = Base64.getEncoder().encodeToString(bytes);
                        parseClass(bytes, e);
                        ok++;
                    } catch (Throwable t) {
                        e.error = t.getClass().getSimpleName() + ": " + t.getMessage();
                        fail++;
                    }

                    // ---- dynamic native-flag unlock, part 1 (static, ASM) ----
                    // Strip ACC_NATIVE and give every native method a real body,
                    // so the class can be loaded & verified WITHOUT the DLL.
                    if (e.nativeCount > 0) {
                        try {
                            byte[] patched = stripNativeFlags(e.bytecode, e);
                            e.patchedBytes = patched;
                            e.patchedBytecodeBase64 = Base64.getEncoder().encodeToString(patched);
                            e.patched = true;
                            patchedMap.put(e.path, patched);
                        } catch (Throwable t) {
                            out.println("[patch] FAILED " + e.path + ": " + t);
                        }
                    }

                    // Only add to results if class has at least one native method
                    if (hasNativeMethod(e)) {
                        results.add(e);
                    } else {
                        filtered++;
                    }
                }
            }

            // sort for stable output
            results.sort(Comparator.comparing(a -> a.path));

            // ---- dynamic native-flag unlock, part 2 (runtime reflection/JNI) ----
            if (Boolean.getBoolean("jpi.dynamic")) {
                out.println();
                out.println("=== Dynamic native unlock attempt (-Djpi.dynamic=true) ===");
                try {
                    dynamicUnlock(results, out);
                } catch (Throwable t) {
                    out.println("[dynamic] aborted: " + t);
                }
            } else {
                out.println();
                out.println("(tip: re-run with -Djpi.dynamic=true to also attempt the runtime");
                out.println("       defineClass/getDeclaredModifiers/RegisterNatives unlock path)");
            }

            Path desktop = Paths.get(System.getProperty("user.home"), "Desktop");
            Files.createDirectories(desktop);
            Path output = desktop.resolve("obf_bytecode_dump.json");

            // also write next to the jar if desktop fails for any reason
            String json = toJson(jarPath, results, total, ok, fail);
            try {
                Files.writeString(output, json, StandardCharsets.UTF_8);
                out.println("Saved: " + output.toAbsolutePath());
            } catch (Throwable t) {
                Path fallback = jarPath.getParent().resolve("obf_bytecode_dump.json");
                Files.writeString(fallback, json, StandardCharsets.UTF_8);
                out.println("Desktop write failed, saved to: " + fallback.toAbsolutePath());
            }

            // convenience artifact: write the patched classes into a sibling folder
            // so you can immediately test patching them back into the JAR.
            if (!patchedMap.isEmpty()) {
                Path pdir = Paths.get(System.getProperty("jpi.patchdir",
                                          "obf_bytecode_dump_patch"));
                Files.createDirectories(pdir);
                for (Map.Entry<String, byte[]> pe : patchedMap.entrySet()) {
                    Path f = pdir.resolve(pe.getKey());
                    Files.createDirectories(f.getParent());
                    Files.write(f, pe.getValue());
                }
                out.println("Patched .class files written to: " + pdir.toAbsolutePath());
            }

            out.println("Scanned: " + total + "  OK: " + ok + "  Failed: " + fail
                        + "  Filtered (no native): " + filtered);
            out.println("JSON entries: " + results.size());
        } catch (Throwable t) {
            t.printStackTrace(out);
        }
    }

    /** Check if an Entry has at least one native method */
    static boolean hasNativeMethod(Entry e) {
        for (MethodInfo m : e.methods) {
            if (m.isNative) return true;
        }
        return false;
    }

    /** Parse class header + methods/fields with ASM (no frames needed). */
    static void parseClass(byte[] data, Entry e) {
        new ClassReader(data).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visit(int version, int access, String name, String signature,
                              String superName, String[] interfaces) {
                e.internalName = name;
                e.access = access;
                e.superName = superName;
                if (interfaces != null) {
                    for (String i : interfaces) e.interfaces.add(i);
                }
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                             String signature, String[] exceptions) {
                MethodInfo m = new MethodInfo();
                m.name = name;
                m.desc = desc;
                m.access = access;
                m.isNative = (access & Opcodes.ACC_NATIVE) != 0;
                if (m.isNative) e.nativeCount++;
                e.methods.add(m);
                return null;
            }

            @Override
            public FieldVisitor visitField(int access, String name, String desc,
                                           String signature, Object value) {
                FieldInfo f = new FieldInfo();
                f.name = name;
                f.desc = desc;
                f.access = access;
                e.fields.add(f);
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    }

    // =====================================================================
    // Static "unlock": rewrite the .class so no method is native anymore
    // =====================================================================

    /**
     * Rebuild the class with ASM: every ACC_NATIVE method loses the native
     * flag and receives a generated Code attribute (a stub body). Everything
     * else (non-native methods incl. their code, fields, attributes) is
     * copied through untouched.
     */
    static byte[] stripNativeFlags(byte[] original, Entry e) {
        ClassReader cr = new ClassReader(original);
        ClassWriter cw = new ClassWriter(cr, 0);

        cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                             String signature, String[] exceptions) {
                if ((access & Opcodes.ACC_NATIVE) == 0) {
                    return super.visitMethod(access, name, desc, signature, exceptions);
                }
                int newAccess = access & ~Opcodes.ACC_NATIVE;
                // NOTE: do NOT delegate to the wrapped visitor here - that would
                // copy the original (empty) method body. Emit our stub instead.
                MethodVisitor mv = cv.visitMethod(newAccess, name, desc, signature, exceptions);
                emitStubBody(mv, name, desc, newAccess);
                return null;
            }
        }, 0); // keep Code attributes of non-native methods

        byte[] patched = cw.toByteArray();

        // sanity check: re-parse the patched bytes and count leftover natives
        final int[] stillNative = {0};
        new ClassReader(patched).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                             String signature, String[] exceptions) {
                if ((access & Opcodes.ACC_NATIVE) != 0) stillNative[0]++;
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        if (stillNative[0] != 0) {
            throw new IllegalStateException("stripNativeFlags left "
                    + stillNative[0] + " native methods in " + e.path);
        }
        return patched;
    }

    /** Generate a minimal valid method body for a de-nativized method. */
    static void emitStubBody(MethodVisitor mv, String name, String desc, int access) {
        Type ret = Type.getReturnType(desc);
        mv.visitCode();
        boolean init = "<init>".equals(name);
        switch (ret.getSort()) {
            case Type.VOID:
                if (init) {
                    // super() call so <init> stays verifier-valid
                    mv.visitVarInsn(Opcodes.ALOAD, 0);
                    mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object",
                                       "<init>", "()V", false);
                }
                mv.visitInsn(Opcodes.RETURN);
                break;
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT:
                if (init) emitSuperCall(mv);
                mv.visitInsn(Opcodes.ICONST_0);
                mv.visitInsn(Opcodes.IRETURN);
                break;
            case Type.LONG:
                if (init) emitSuperCall(mv);
                mv.visitInsn(Opcodes.LCONST_0);
                mv.visitInsn(Opcodes.LRETURN);
                break;
            case Type.FLOAT:
                if (init) emitSuperCall(mv);
                mv.visitInsn(Opcodes.FCONST_0);
                mv.visitInsn(Opcodes.FRETURN);
                break;
            case Type.DOUBLE:
                if (init) emitSuperCall(mv);
                mv.visitInsn(Opcodes.DCONST_0);
                mv.visitInsn(Opcodes.DRETURN);
                break;
            default: { // OBJECT / ARRAY
                if (init) {
                    emitSuperCall(mv);
                    mv.visitInsn(Opcodes.ACONST_NULL);
                } else {
                    // return-type-specific null is fine as ACONST_NULL
                    mv.visitTypeInsn(Opcodes.NEW, "java/lang/UnsatisfiedLinkError");
                    mv.visitInsn(Opcodes.DUP);
                    mv.visitLdcInsn("native impl stubbed: " + name + desc);
                    mv.visitMethodInsn(Opcodes.INVOKESPECIAL,
                        "java/lang/UnsatisfiedLinkError", "<init>",
                        "(Ljava/lang/String;)V", false);
                    mv.visitInsn(Opcodes.ATHROW);
                }
                mv.visitInsn(Opcodes.ARETURN);
                break;
            }
        }
        mv.visitMaxs(8, maxLocals(desc, (access & Opcodes.ACC_STATIC) != 0));
        mv.visitEnd();
    }

    static void emitSuperCall(MethodVisitor mv) {
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object",
                           "<init>", "()V", false);
    }

    static int maxLocals(String desc, boolean isStatic) {
        int n = isStatic ? 0 : 1;
        for (Type t : Type.getArgumentTypes(desc)) {
            n += t.getSize();
        }
        return n + 4; // slack, COMPUTE_FRAMES off so exact numbers don't matter much
    }

    // =====================================================================
    // Runtime "dynamic" unlock: define patched classes, strip the flag in
    // memory, and try to bind the DLL's implementations via raw JNI.
    // =====================================================================

    static void dynamicUnlock(List<Entry> entries, PrintStream out) throws Exception {
        out.println("JDK: " + System.getProperty("java.version")
                    + "  os: " + System.getProperty("os.name")
                    + "  arch: " + System.getProperty("os.arch"));

        // 1) extract native/x64-windows.dll from the jar (if present)
        Path jarPath = Paths.get(System.getProperty("super.jar", DEFAULT_JAR));
        if (!Files.isRegularFile(jarPath)) {
            Path alt = Paths.get("attachments", DEFAULT_JAR);
            if (Files.isRegularFile(alt)) jarPath = alt;
        }
        Path dllTmp = null;
        try (JarFile jf = new JarFile(jarPath.toFile())) {
            JarEntry d = jf.getJarEntry("native/x64-windows.dll");
            if (d != null) {
                dllTmp = Files.createTempFile("everyday-native-", ".dll");
                try (InputStream in = jf.getInputStream(d)) {
                    Files.copy(in, dllTmp, StandardCopyOption.REPLACE_EXISTING);
                }
                out.println("[dyn] extracted DLL -> " + dllTmp);
            } else {
                out.println("[dyn] native/x64-windows.dll not found in jar");
            }
        }

        // 2) parse the PE export table for JNI_OnLoad / RegisterNatives helpers
        if (dllTmp != null) {
            try {
                PeInfo pe = parsePeExports(dllTmp, out);
                out.println("[dyn] PE machine=0x" + Integer.toHexString(pe.machine)
                            + " exports=" + pe.exports);
                if (pe.machine != 0x8664) {
                    out.println("[dyn] not an x64 PE - skipping raw-JNI binding "
                                + "(this analysis host is likely Linux/arm)");
                }
            } catch (Throwable t) {
                out.println("[dyn] PE parse failed: " + t);
            }
        }

        // 3) define the PATCHED (de-nativized) classes dynamically and prove
        //    the native flag is gone at runtime. Version downgrade retries are
        //    handled inside loadViaChildLoader, so we pass the raw patched
        //    bytes here (JSON keeps the original v65 for real deployment).
        boolean definedAny = false;
        for (Entry e : entries) {
            if (!e.patched) continue;
            Class<?> c = defineClassDynamically(e, e.patchedBytes, out);
            if (c == null) continue;
            definedAny = true;
            int natives = countNativeReflectively(c);
            // cross-check against the patched BYTES themselves: reflection on a
            // class loaded via parent-delegation may return the JAR's original
            // (still-native) version instead of our patched bytes.
            int nativesInBytes = countNativeInBytes(e.patchedBytes);
            String note = (natives != nativesInBytes)
                    ? "  [!] reflection saw the parent-loaded ORIGINAL; "
                      + "patched bytes themselves contain " + nativesInBytes + " natives"
                    : "";
            out.println("[dyn] defined " + e.internalName
                        + "  declaredMethods=" + c.getDeclaredMethods().length
                        + "  remainingNative=" + natives
                        + "  (was " + e.nativeCount + ")" + note);
        }
        if (!definedAny) {
            out.println("[dyn] could not define any class dynamically on this JVM "
                        + "(defineClass unavailable); static ASM patch in the JSON "
                        + "is still valid.");
        }
    }

    /** Highest class-file major version this JVM accepts (e.g. 61 for JDK 17). */
    static int maxSupportedClassVersion() {
        try {
            String v = System.getProperty("java.class.version"); // e.g. "61.0"
            return Integer.parseInt(v.split("\\.")[0]);
        } catch (Throwable t) {
            return 52; // safe fallback
        }
    }

    static void out0(PrintStream out, String s) { if (out != null) out.println("[dyn] " + s); }

    /** Try several mechanisms to define a class at runtime without a full loader. */
    static Class<?> defineClassDynamically(Entry e, byte[] bytes, PrintStream out) {
        // A) JDK 9+: MethodHandles.Lookup#defineClass. The defining Lookup MUST
        //    be in the same package as the new class, and the package must
        //    already be defined by that same loader. NOTE: we deliberately do
        //    NOT call ClassLoader#getPackage here - it is protected and does
        //    not compile from outside ClassLoader subclasses. We just probe
        //    directly and fall through on failure.
        try {
            String pkgName = e.internalName.contains("/")
                ? e.internalName.substring(0, e.internalName.lastIndexOf('/')).replace('/', '.')
                : "";
            if (!pkgName.isEmpty()) {
                ClassLoader pl = JpiSnippet.class.getClassLoader();
                // anchor class in the SAME package & loader (package-private
                // classes are fine for privateLookupIn)
                Class<?> anchor = Class.forName(pkgName + ".package-info", false, pl);
                MethodHandles.Lookup lookup =
                    MethodHandles.privateLookupIn(anchor, MethodHandles.lookup());
                Class<?> c = lookup.defineClass(bytes);
                out0(out, "defineClass(" + e.internalName + ") via Lookup.defineClass");
                return c;
            }
        } catch (Throwable ignored) {}

        // B) JDK <=8: Unsafe.defineAnonymousClass (removed in JDK 17+)
        try {
            Class<?> unsafeCls = Class.forName("sun.misc.Unsafe");
            Field theUnsafe = unsafeCls.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            Object unsafe = theUnsafe.get(null);
            Method m = unsafeCls.getMethod("defineAnonymousClass", Class.class, byte[].class, Object[].class);
            Class<?> c = (Class<?>) m.invoke(unsafe, Object.class, bytes, null);
            out0(out, "defineClass(" + e.internalName + ") via Unsafe.defineAnonymousClass");
            return c;
        } catch (Throwable ignored) {}

        // C) last resort: throwaway child ClassLoader with classpath = the JAR,
        //    plus automatic class-version downgrade retries (see
        //    loadViaChildLoader). Still fully dynamic - nothing is written to
        //    disk or added to the app classpath. Performs a real JVM parse +
        //    verification of the patched bytes.
        try {
            // If the target package is NOT yet loaded by any loader on this JVM
            // (the usual case for an offline dump), Lookup#defineClass can't be
            // used; go straight to the child-loader path without spamming a
            // confusing "FAILED" line first.
            boolean pkgDefined = !Package.getPackages().toString().isEmpty()
                    && findAnyClassInPackage(e.internalName, JpiSnippet.class.getClassLoader()) != null;
            if (!pkgDefined && e.internalName.indexOf('/') >= 0) {
                Class<?> c = loadViaChildLoader(e, bytes, out);
                out0(out, "defineClass(" + e.internalName
                          + ") via throwaway child ClassLoader (verified by JVM)"
                          + "  [Lookup.defineClass skipped: package '"
                          + e.internalName.substring(0, e.internalName.lastIndexOf('/'))
                          + "' not defined in this JVM]");
                return c;
            }
            Class<?> c = loadViaChildLoader(e, bytes, out);
            out0(out, "defineClass(" + e.internalName + ") via throwaway child ClassLoader (verified by JVM)");
            return c;
        } catch (Throwable t) {
            Throwable root = t;
            while (root.getCause() != null && root.getCause() != root) root = root.getCause();
            out0(out, "defineClass FAILED for " + e.internalName + ": "
                      + t.getClass().getSimpleName() + " -> " + root);
            out0(out, "   (class was still verified by ASM; use patchedBytecodeBase64 / "
                      + "the .class in obf_bytecode_dump_patch/ for the offline patch path)");
            return null;
        }
    }

    /**
     * Child-first ClassLoader: for its single target class it defines the
     * supplied (patched) bytes itself instead of delegating to the parent -
     * otherwise the parent would return the ORIGINAL still-native class from
     * the JAR and our patched bytes would never be used. All other classes
     * delegate normally (parent = URLClassLoader over the JAR, so sibling
     * obf/* classes resolve fine).
     */
    static final class ChildLoader extends ClassLoader {
        private final String name;
        private final byte[] bytes;
        ChildLoader(ClassLoader parent, String name, byte[] bytes) {
            super(parent);
            this.name = name;
            this.bytes = bytes;
        }
        @Override protected Class<?> loadClass(String n, boolean resolve)
                throws ClassNotFoundException {
            synchronized (getClassLoadingLock(n)) {
                Class<?> c = findLoadedClass(n);
                if (c == null) {
                    if (n.equals(name)) {
                        c = findClass(n);           // OUR patched bytes, child-first
                    } else {
                        c = getParent().loadClass(n); // everything else: JAR / JDK
                    }
                }
                if (resolve) resolveClass(c);
                return c;
            }
        }
        @Override protected Class<?> findClass(String n) throws ClassNotFoundException {
            if (n.equals(name)) return defineClass(n, bytes, 0, bytes.length);
            throw new ClassNotFoundException(n);
        }
    }

    /**
     * Load a patched class in a throwaway child ClassLoader whose PARENT is a
     * URLClassLoader over the target JAR. If the JVM rejects the class-file
     * version (e.g. v65 on JDK 17), rewrite the major version and retry until
     * the JVM accepts it. This gives a real parse + verification of the
     * de-nativized bytes without touching disk or the app classpath.
     */
    static Class<?> loadViaChildLoader(Entry e, byte[] bytes, PrintStream out) throws Exception {
        Path jp = Paths.get(System.getProperty("super.jar", DEFAULT_JAR));
        if (!Files.isRegularFile(jp)) {
            Path alt2 = Paths.get("attachments", DEFAULT_JAR);
            if (Files.isRegularFile(alt2)) jp = alt2;
        }
        ClassLoader base;
        try {
            java.net.URL jarUrl = jp.toUri().toURL();
            base = new java.net.URLClassLoader("jpi-jar-cp", new java.net.URL[]{jarUrl},
                    JpiSnippet.class.getClassLoader());
        } catch (Throwable t) {
            base = JpiSnippet.class.getClassLoader();
        }
        String cn = e.internalName.replace('/', '.');
        int ver = ((bytes[6] & 0xff) << 8) | (bytes[7] & 0xff);
        int jvmMax = maxSupportedClassVersion();
        Throwable last = null;
        // IMPORTANT: child-first loading. If the parent (URLClassLoader over
        // the JAR) is asked first it will happily return the ORIGINAL, still
        // native class from the JAR and our patched bytes are never used.
        // So ChildLoader overrides loadClass() to define its own bytes first.
        List<Integer> tries = new ArrayList<>();
        tries.add(ver);
        for (int v = jvmMax; v >= 45 && v < ver; v--) { tries.add(v); if (tries.size() > 6) break; }
        for (int tv : tries) {
            byte[] cur = (tv == ver) ? bytes : bytes.clone();
            if (tv != ver) { cur[6] = 0; cur[7] = (byte) tv; }
            try {
                ChildLoader cl = new ChildLoader(base, cn, cur);
                Class<?> c = cl.loadClass(cn);   // child-first: defines OUR bytes
                if (tv != ver) {
                    out0(out, cn + ": class v" + ver + " -> retried with v" + tv + " -> accepted by JVM");
                }
                return c;
            } catch (UnsupportedClassVersionError u) {
                last = u; // try next lower version
            } catch (ClassNotFoundException | NoClassDefFoundError t) {
                last = t; break; // sibling classes unresolvable - not a version issue
            }
        }
        throw new RuntimeException(last != null ? String.valueOf(last) : "load failed");
    }

    /**
     * (currently unused helper) Find any already-loaded class inside the given
     * package to use as a privateLookupIn anchor. Package.getPackages() only
     * lists defined-and-referenced packages, so this is best-effort.
     */
    static Class<?> findAnyClassInPackage(String pkgName, ClassLoader cl) {
        try {
            for (Package p : Package.getPackages()) {
                if (p.getName().equals(pkgName)) {
                    return null; // handled by caller fallback (C)
                }
            }
        } catch (Throwable ignored) {}
        return null;
    }

    /** Count native methods reflectively; uses getDeclaredModifiers on JDK21+ if possible. */
    static int countNativeReflectively(Class<?> c) {
        int n = 0;
        for (Method m : c.getDeclaredMethods()) {
            if (Modifier.isNative(m.getModifiers())) n++;
        }
        return n;
    }

    /** Count ACC_NATIVE methods directly in the given class-file bytes (ASM). */
    static int countNativeInBytes(byte[] classFile) {
        final int[] n = {0};
        try {
            new ClassReader(classFile).accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc,
                                                 String signature, String[] exceptions) {
                    if ((access & Opcodes.ACC_NATIVE) != 0) n[0]++;
                    return null;
                }
            }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        } catch (Throwable ignored) {}
        return n[0];
    }

    // ----- tiny PE export-table parser (proves what the DLL exposes) -----
    static final class PeInfo {
        int machine;
        long imageBase;
        List<String> exports = new ArrayList<>();
    }

    static PeInfo parsePeExports(Path dll, PrintStream out) throws IOException {
        byte[] b = Files.readAllBytes(dll);
        PeInfo info = new PeInfo();
        int lfanew = le32(b, 0x3c);
        if (lfanew < 0 || lfanew + 24 > b.length) throw new IOException("bad e_lfanew");
        if (le32(b, lfanew) != 0x00004550) throw new IOException("bad PE sig");
        info.machine = le16(b, lfanew + 4);
        int numSec = le16(b, lfanew + 6);
        int optSize = le16(b, lfanew + 20);
        int optOff = lfanew + 24;
        boolean plus = le16(b, optOff) == 0x20b; // PE32+
        info.imageBase = plus ? le64(b, optOff + 24) : (le32(b, optOff + 28) & 0xffffffffL);
        long expRva = plus ? le32(b, optOff + 112) & 0xffffffffL : le32(b, optOff + 96) & 0xffffffffL;
        int secOff = optOff + optSize;

        for (int i = 0; i < numSec && secOff + (i + 1) * 40 <= b.length; i++) {
            int so = secOff + i * 40;
            long vaddr = le32(b, so + 12) & 0xffffffffL;
            long vsize = le32(b, so + 8)  & 0xffffffffL;
            long raw   = le32(b, so + 16) & 0xffffffffL;
            long rsize = le32(b, so + 20) & 0xffffffffL;
            if (raw == 0 && rsize == 0) continue; // virtual-only section
            if (raw + rsize > b.length) rsize = Math.max(0, b.length - (int) raw);
            secs.add(new int[]{(int) vaddr, (int) vsize, (int) raw, (int) rsize});
        }
        Function<Long, Integer> rvaToOff = rva -> {
            for (int[] s : secs) {
                long va = s[0] & 0xffffffffL;
                long vs = s[1] & 0xffffffffL;
                long rs = s[3] & 0xffffffffL;
                if (rva >= va && rva < va + vs) {
                    long delta = rva - va;
                    if (delta < rs) {                 // inside real on-disk data
                        int off = s[2] + (int) delta;
                        if (off >= 0 && off < b.length) return off;
                    }
                    return -1;                        // mapped but not in file
                }
            }
            return -1;
        };
        if (expRva != 0) {
            int eo = rvaToOff.apply(expRva);
            if (eo >= 0 && eo + 40 <= b.length) {
                int names = le32(b, eo + 24);
                int nameTblRva = le32(b, eo + 32);
                int nameTbl = rvaToOff.apply((long) nameTblRva);
                if (names > 4096) names = 4096; // paranoia cap
                for (int i = 0; i < names && nameTbl >= 0
                        && nameTbl + (i + 1) * 4 <= b.length; i++) {
                    int strRva = le32(b, nameTbl + i * 4);
                    int strOff = rvaToOff.apply((long) strRva);
                    if (strOff < 0) continue;
                    int end = strOff;
                    while (end < b.length && b[end] != 0) end++;
                    if (end - strOff > 256) continue;
                    info.exports.add(new String(b, strOff, end - strOff, StandardCharsets.US_ASCII));
                }
            } else {
                out0(out, "[dyn] export RVA 0x" + Long.toHexString(expRva)
                             + " not mapped to file data (packed/VMProtected PE)");
            }
        }
        if (info.exports.size() > 64) info.exports = info.exports.subList(0, 64);
        return info;
    }

    static int le16(byte[] b, int o) { return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8); }
    static int le32(byte[] b, int o) {
        return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8) | ((b[o + 2] & 0xff) << 16) | ((b[o + 3] & 0xff) << 24);
    }
    static long le64(byte[] b, int o) { return (le32(b, o) & 0xffffffffL) | ((long) le32(b, o + 4) << 32); }

    static String toJson(Path jar, List<Entry> list, int total, int ok, int fail) {
        StringBuilder sb = new StringBuilder(1 << 20);
        sb.append("{\n");
        sb.append("  \"jar\": "); quote(sb, jar.toString());
        sb.append(",\n  \"total\": ").append(total);
        sb.append(",\n  \"ok\": ").append(ok);
        sb.append(",\n  \"failed\": ").append(fail);
        sb.append(",\n  \"classes\": [\n");

        for (int i = 0; i < list.size(); i++) {
            Entry e = list.get(i);
            if (i > 0) sb.append(",\n");
            sb.append("    {\n");
            sb.append("      \"path\": "); quote(sb, e.path);
            sb.append(",\n      \"internalName\": ");
            if (e.internalName == null) sb.append("null");
            else quote(sb, e.internalName);
            sb.append(",\n      \"size\": ").append(e.size);
            sb.append(",\n      \"access\": ").append(e.access);
            sb.append(",\n      \"superName\": ");
            if (e.superName == null) sb.append("null");
            else quote(sb, e.superName);

            sb.append(",\n      \"interfaces\": [");
            for (int j = 0; j < e.interfaces.size(); j++) {
                if (j > 0) sb.append(", ");
                quote(sb, e.interfaces.get(j));
            }
            sb.append("]");

            // methods
            sb.append(",\n      \"methods\": [");
            for (int j = 0; j < e.methods.size(); j++) {
                MethodInfo m = e.methods.get(j);
                if (j > 0) sb.append(", ");
                sb.append("{\"name\":"); quote(sb, m.name);
                sb.append(",\"desc\":"); quote(sb, m.desc);
                sb.append(",\"access\":").append(m.access);
                sb.append(",\"native\":").append(m.isNative);
                sb.append(",\"nativeStripped\":").append(m.isNative && e.patched);
                sb.append("}");
            }
            sb.append("]");

            // fields
            sb.append(",\n      \"fields\": [");
            for (int j = 0; j < e.fields.size(); j++) {
                FieldInfo f = e.fields.get(j);
                if (j > 0) sb.append(", ");
                sb.append("{\"name\":"); quote(sb, f.name);
                sb.append(",\"desc\":"); quote(sb, f.desc);
                sb.append(",\"access\":").append(f.access);
                sb.append("}");
            }
            sb.append("]");

            sb.append(",\n      \"nativeCount\": ").append(e.nativeCount);
            sb.append(",\n      \"patched\": ").append(e.patched);

            // the actual bytecode (base64)
            sb.append(",\n      \"bytecodeBase64\": ");
            if (e.bytecodeBase64 == null) sb.append("null");
            else quote(sb, e.bytecodeBase64);

            // the DE-NATIVIZED bytecode (base64) - ready to patch back into the JAR
            sb.append(",\n      \"patchedBytecodeBase64\": ");
            if (e.patchedBytecodeBase64 == null) sb.append("null");
            else quote(sb, e.patchedBytecodeBase64);

            sb.append(",\n      \"error\": ");
            if (e.error == null) sb.append("null");
            else quote(sb, e.error);

            sb.append("\n    }");
        }
        sb.append("\n  ]\n}\n");
        return sb.toString();
    }

    static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 32) {
                        String hex = Integer.toHexString(c);
                        sb.append("\\u");
                        for (int j = hex.length(); j < 4; j++) sb.append('0');
                        sb.append(hex);
                    } else sb.append(c);
            }
        }
        sb.append('"');
    }

    // allow running as plain main for convenience
    public static void main(String[] args) {
        execute(System.out);
    }
}
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.util;

import com.sun.jna.Library;
import com.sun.jna.Native;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Utility for locating and loading native DLLs via JNA.
 *
 * <p>Search order for a given DLL name:
 * <ol>
 *   <li>{@code src/main/java/com/huawei/umdk/snc/util}</li>
 *   <li>current working directory ({@code user.dir})</li>
 *   <li>application directory (location of the JAR or class roots)</li>
 *   <li>{@code target}</li>
 *   <li>{@code target/classes}</li>
 * </ol>
 * When the DLL is found its parent directory is published as
 * {@code jna.library.path} before loading.
 *
 * <p>If no candidate is found on disk, the library is extracted from the
 * classpath (e.g. packaged inside the JAR under {@code src/main/resources})
 * to a temp directory and loaded from there. As a last resort the loader
 * falls back to {@link Native#load(String, Class)} with the bare library
 * name so JNA can resolve it from system paths.
 */
public final class DllLoader {

    private DllLoader() {
    }

    /**
     * Loads a native library via JNA, searching the canonical path list first.
     *
     * @param dllName        the DLL file name, e.g. {@code "libubswitch.dll"}
     * @param interfaceClass the JNA interface class to bind the library to
     * @param <T>            library interface type, must extend {@link Library}
     * @return the bound library proxy returned by {@link Native#load}
     */
    public static <T extends Library> T load(String dllName, Class<T> interfaceClass) {
        return load(dllName, interfaceClass, null);
    }

    /**
     * Loads a native library via JNA, searching the canonical path list first.
     *
     * @param dllName        the DLL file name, e.g. {@code "libubswitch.dll"}
     * @param interfaceClass the JNA interface class to bind the library to
     * @param options        extra JNA options (e.g. FunctionMapper); may be {@code null}
     * @param <T>            library interface type, must extend {@link Library}
     * @return the bound library proxy returned by {@link Native#load}
     */
    public static <T extends Library> T load(String dllName, Class<T> interfaceClass,
                                             Map<String, Object> options) {
        System.setProperty("jna.encoding", "UTF-8");

        String dllPath = findDllPath(dllName);
        if (dllPath != null) {
            File dllFile = new File(dllPath);
            String parentDir = dllFile.getParent();
            if (parentDir != null) {
                System.setProperty("jna.library.path", parentDir);
            }
            return Native.load(dllPath, interfaceClass, options != null ? options : new java.util.HashMap<>());
        }
        String extractedPath = extractFromClasspath(dllName);
        if (extractedPath != null) {
            File extractedFile = new File(extractedPath);
            File parentDir = extractedFile.getParentFile();
            if (parentDir != null) {
                System.setProperty("jna.library.path", parentDir.getAbsolutePath());
            }
            return Native.load(extractedPath, interfaceClass, options != null ? options : new java.util.HashMap<>());
        }
        return Native.load(dllName, interfaceClass, options != null ? options : new java.util.HashMap<>());
    }

    /**
     * Extracts a native library packaged as a classpath resource (inside a
     * JAR or under {@code target/classes}) into a per-user temp directory.
     *
     * @param dllName the resource / DLL file name, e.g. {@code "libubswitch.dll"}
     * @return the absolute path of the extracted file, or {@code null} when
     *         no matching classpath resource exists
     */
    private static String extractFromClasspath(String dllName) {
        List<String> resourceNames = new ArrayList<>();
        resourceNames.add(dllName);
        resourceNames.add("com/huawei/umdk/snc/util/" + dllName);

        for (String resourceName : resourceNames) {
            try (InputStream in = DllLoader.class.getClassLoader()
                    .getResourceAsStream(resourceName)) {
                if (in == null) {
                    continue;
                }
                File tmpDir = new File(System.getProperty("java.io.tmpdir"),
                                       "ubSwitch-native");
                if (!tmpDir.exists() && !tmpDir.mkdirs()) {
                    return null;
                }
                File target = new File(tmpDir, dllName);
                try (OutputStream out = new FileOutputStream(target)) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        out.write(buf, 0, n);
                    }
                }
                return target.getAbsolutePath();
            } catch (IOException e) {
                return null;
            }
        }
        return null;
    }

    private static String findDllPath(String dllName) {
        for (String dir : buildSearchPaths()) {
            if (dir == null) {
                continue;
            }
            File candidate = new File(dir, dllName);
            if (candidate.exists() && candidate.isFile()) {
                return candidate.getAbsolutePath();
            }
        }
        return null;
    }

    private static List<String> buildSearchPaths() {
        List<String> paths = new ArrayList<>();
        paths.add("src/main/resources");
        paths.add(System.getProperty("user.dir"));
        paths.add(getApplicationDir());
        paths.add("target");
        paths.add("target/classes");
        return paths;
    }

    private static String getApplicationDir() {
        try {
            URL location = DllLoader.class.getProtectionDomain().getCodeSource().getLocation();
            if (location != null) {
                File file = new File(location.toURI());
                if (file.isFile()) {
                    return file.getParent();
                }
                return file.getAbsolutePath();
            }
        } catch (URISyntaxException | RuntimeException e) {
            // fall through to user.dir
        }
        return System.getProperty("user.dir");
    }
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.util;

import java.util.regex.Pattern;

public final class AddressUtils {

    private static final Pattern IPV4_PATTERN =
        Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");

    private static final Pattern EID_PATTERN = Pattern.compile("^[0-9a-fA-F]{32}$");

    private AddressUtils() {
    }

    public static String applyMask(String targetAddr, int maskLength) {
        if (targetAddr == null || maskLength < 0 || maskLength > 32) {
            return targetAddr;
        }
        int ipInt = ipToInt(targetAddr);
        int mask = maskLength == 0 ? 0 : (-1) << (32 - maskLength);
        return intToIp(ipInt & mask);
    }

    public static int ipToInt(String ip) {
        if (ip == null) {
            throw new IllegalArgumentException("IP address must not be null");
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException(
                "Invalid IPv4 address (expected 4 octets): " + ip);
        }
        int result = 0;
        for (int i = 0; i < 4; i++) {
            int octet;
            try {
                octet = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                    "Invalid IPv4 address (non-numeric octet): " + ip, e);
            }
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException(
                    "Invalid IPv4 address (octet out of range 0-255): " + ip);
            }
            result = (result << 8) | octet;
        }
        return result;
    }

    public static String intToIp(int ipInt) {
        return ((ipInt >> 24) & 0xFF) + "."
            + ((ipInt >> 16) & 0xFF) + "."
            + ((ipInt >> 8) & 0xFF) + "."
            + (ipInt & 0xFF);
    }

    public static boolean isValidCna(String cna) {
        if (cna == null) {
            return false;
        }
        java.util.regex.Matcher matcher = IPV4_PATTERN.matcher(cna);
        if (!matcher.matches()) {
            return false;
        }
        for (int i = 1; i <= 4; i++) {
            int octet = Integer.parseInt(matcher.group(i));
            if (octet > 255) {
                return false;
            }
        }
        return true;
    }

    public static boolean isValidEid(String eid) {
        return eid != null && EID_PATTERN.matcher(eid).matches();
    }
}

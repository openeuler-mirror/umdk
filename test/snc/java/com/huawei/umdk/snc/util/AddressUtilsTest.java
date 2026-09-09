/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: address utils test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.util;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("AddressUtils Utility")
class AddressUtilsTest {

    @Nested
    @DisplayName("applyMask")
    class ApplyMaskTest {

        @Test
        @DisplayName("null targetAddr returns null")
        void nullInput() {
            assertNull(AddressUtils.applyMask(null, 24));
        }

        @Test
        @DisplayName("zero mask returns 0.0.0.0")
        void zeroMask() {
            assertEquals("0.0.0.0", AddressUtils.applyMask("10.0.0.5", 0));
        }

        @Test
        @DisplayName("32 mask returns same IP")
        void mask32() {
            assertEquals("10.0.0.5", AddressUtils.applyMask("10.0.0.5", 32));
        }

        @Test
        @DisplayName("24 mask truncates last octet")
        void mask24() {
            assertEquals("10.0.0.0", AddressUtils.applyMask("10.0.0.5", 24));
        }

        @Test
        @DisplayName("16 mask truncates last two octets")
        void mask16() {
            assertEquals("10.0.0.0", AddressUtils.applyMask("10.0.5.5", 16));
        }

        @Test
        @DisplayName("8 mask truncates last three octets")
        void mask8() {
            assertEquals("10.0.0.0", AddressUtils.applyMask("10.5.5.5", 8));
        }

        @Test
        @DisplayName("negative mask returns targetAddr unchanged")
        void negativeMask() {
            assertEquals("10.0.0.5", AddressUtils.applyMask("10.0.0.5", -1));
        }

        @Test
        @DisplayName("mask > 32 returns targetAddr unchanged")
        void maskOver32() {
            assertEquals("10.0.0.5", AddressUtils.applyMask("10.0.0.5", 33));
        }
    }

    @Nested
    @DisplayName("ipToInt")
    class IpToIntTest {

        @Test
        @DisplayName("0.0.0.0 returns 0")
        void zero() {
            assertEquals(0, AddressUtils.ipToInt("0.0.0.0"));
        }

        @Test
        @DisplayName("255.255.255.255 returns -1")
        void allOnes() {
            assertEquals(-1, AddressUtils.ipToInt("255.255.255.255"));
        }

        @Test
        @DisplayName("170.170.170.18 returns expected value")
        void specificValue() {
            int expected = (170 << 24) | (170 << 16) | (170 << 8) | 18;
            assertEquals(expected, AddressUtils.ipToInt("170.170.170.18"));
        }

        @Test
        @DisplayName("10.0.0.1 returns expected value")
        void tenDotZero() {
            int expected = (10 << 24) | (0 << 16) | (0 << 8) | 1;
            assertEquals(expected, AddressUtils.ipToInt("10.0.0.1"));
        }
    }

    @Nested
    @DisplayName("intToIp")
    class IntToIpTest {

        @Test
        @DisplayName("0 returns 0.0.0.0")
        void zero() {
            assertEquals("0.0.0.0", AddressUtils.intToIp(0));
        }

        @Test
        @DisplayName("expected value returns IP string")
        void specificValue() {
            int ipInt = (170 << 24) | (170 << 16) | (170 << 8) | 18;
            assertEquals("170.170.170.18", AddressUtils.intToIp(ipInt));
        }

        @Test
        @DisplayName("round-trip consistency")
        void roundTrip() {
            String ip = "192.168.1.100";
            assertEquals(ip, AddressUtils.intToIp(AddressUtils.ipToInt(ip)));
        }

        @ParameterizedTest
        @CsvSource({
            "0.0.0.0, 0",
            "255.255.255.255, -1",
            "10.0.0.1, 167772161",
            "192.168.1.1, -1062731519"
        })
        @DisplayName("ipToInt and intToIp round-trip")
        void roundTripParameterized(String ip, int expectedInt) {
            assertEquals(expectedInt, AddressUtils.ipToInt(ip));
            assertEquals(ip, AddressUtils.intToIp(expectedInt));
        }
    }

    @Nested
    @DisplayName("isValidCna")
    class IsValidCnaTest {

        @Test
        @DisplayName("null returns false")
        void nullInput() {
            assertFalse(AddressUtils.isValidCna(null));
        }

        @Test
        @DisplayName("empty returns false")
        void emptyInput() {
            assertFalse(AddressUtils.isValidCna(""));
        }

        @Test
        @DisplayName("non-IP string returns false")
        void invalidFormat() {
            assertFalse(AddressUtils.isValidCna("abc"));
            assertFalse(AddressUtils.isValidCna("1.2.3"));
            assertFalse(AddressUtils.isValidCna("1.2.3.4.5"));
        }

        @Test
        @DisplayName("octet out of range returns false")
        void octetOutOfRange() {
            assertFalse(AddressUtils.isValidCna("256.0.0.1"));
            assertFalse(AddressUtils.isValidCna("1.256.0.1"));
            assertFalse(AddressUtils.isValidCna("1.0.256.1"));
            assertFalse(AddressUtils.isValidCna("1.0.0.256"));
        }

        @Test
        @DisplayName("negative octet returns false")
        void negativeOctet() {
            assertFalse(AddressUtils.isValidCna("-1.0.0.0"));
            assertFalse(AddressUtils.isValidCna("0.-1.0.0"));
            assertFalse(AddressUtils.isValidCna("0.0.-1.0"));
            assertFalse(AddressUtils.isValidCna("0.0.0.-1"));
        }

        @Test
        @DisplayName("valid 4-octet returns true")
        void valid() {
            assertTrue(AddressUtils.isValidCna("0.0.0.0"));
            assertTrue(AddressUtils.isValidCna("255.255.255.255"));
            assertTrue(AddressUtils.isValidCna("10.0.0.1"));
            assertTrue(AddressUtils.isValidCna("170.170.170.18"));
        }
    }

    @Nested
    @DisplayName("isValidEid")
    class IsValidEidTest {

        @Test
        @DisplayName("null returns false")
        void nullInput() {
            assertFalse(AddressUtils.isValidEid(null));
        }

        @Test
        @DisplayName("empty returns false")
        void emptyInput() {
            assertFalse(AddressUtils.isValidEid(""));
        }

        @Test
        @DisplayName("non-hex string returns false")
        void nonHex() {
            assertFalse(AddressUtils.isValidEid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
        }

        @Test
        @DisplayName("wrong length returns false")
        void wrongLength() {
            assertFalse(AddressUtils.isValidEid("0123456789abcdef0123456789abcde"));
            assertFalse(AddressUtils.isValidEid("0123456789abcdef0123456789abcdefg"));
        }

        @Test
        @DisplayName("valid 32-char hex returns true")
        void valid() {
            assertTrue(AddressUtils.isValidEid("0123456789abcdef0123456789abcdef"));
            assertTrue(AddressUtils.isValidEid("00000000000000000000000000000000"));
            assertTrue(AddressUtils.isValidEid("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
        }
    }
}

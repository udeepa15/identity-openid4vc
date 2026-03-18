/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.did.util;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Utility class for Base58 (Bitcoin alphabet) encoding.
 */
public final class Base58 {

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private Base58() {

    }

    /**
     * Encodes the given bytes in Base58.
     *
     * @param input Input bytes.
     * @return Base58 encoded string.
     */
    public static String encode(byte[] input) {
        if (input == null || input.length == 0) {
            return "";
        }

        byte[] inputCopy = Arrays.copyOf(input, input.length);

        int zeros = 0;
        while (zeros < inputCopy.length && inputCopy[zeros] == 0) {
            zeros++;
        }

        byte[] encoded = new byte[inputCopy.length * 2];
        int outputStart = encoded.length;

        for (int inputStart = zeros; inputStart < inputCopy.length; ) {
            encoded[--outputStart] = (byte) ALPHABET.charAt(divmod(inputCopy, inputStart, 256, 58));
            if (inputCopy[inputStart] == 0) {
                inputStart++;
            }
        }

        while (outputStart < encoded.length && encoded[outputStart] == (byte) ALPHABET.charAt(0)) {
            outputStart++;
        }

        while (--zeros >= 0) {
            encoded[--outputStart] = (byte) ALPHABET.charAt(0);
        }

        return new String(encoded, outputStart, encoded.length - outputStart, StandardCharsets.UTF_8);
    }

    /**
     * Divides a number represented as bytes by a divisor and returns the remainder.
     *
     * @param number Number in byte-array form.
     * @param firstDigit Start index.
     * @param base Input base.
     * @param divisor Divisor.
     * @return Remainder.
     */
    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }
}

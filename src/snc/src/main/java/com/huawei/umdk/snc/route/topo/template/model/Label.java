/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: structure related to topology definition
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

@Data
@NoArgsConstructor
public class Label implements  Cloneable{
    private static String mediateChar = ":";

    private static String delimiter = "|";

    @NonNull
    private static Map<String, List<String>> fieldMap = new HashMap<>();

    @NonNull
    private LinkedHashMap<String, String> names = new LinkedHashMap<>();

    public static void setLabelField(@NonNull String nodeType, @NonNull List<String> fields) {
        if (nodeType.isEmpty() || fields.isEmpty() ||
            fields.stream().anyMatch(field -> field == null || field.isEmpty())) {
            throw new IllegalArgumentException("Node type or field item is empty");
        }
        fieldMap.put(nodeType, new ArrayList<>(fields));
    }

    @Override
    public String toString() {
        StringBuilder label = new StringBuilder();
        names.forEach((key, value) -> label.append(key).append(mediateChar).append(value).append(delimiter));
        // Remove the last delimiter character
        int len = label.length();
        if (len > 0) {
            label.setLength(len - delimiter.length());
        }
        return label.toString();
    }

    @Override
    public Label clone() {
        try {
            Label cloned = (Label) super.clone();
            cloned.names = new LinkedHashMap<>(this.names);
            return cloned;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError("clone failed", e);
        }
    }

    public void refreshAllNames(@NonNull String label) {
        LinkedHashMap<String, String> res = new LinkedHashMap<>();
        String[] pairs = label.split(Pattern.quote(delimiter));
        for (String pair : pairs) {
            String[] keyValue = pair.split(mediateChar);
            if (keyValue.length == 2) {
                res.put(keyValue[0], keyValue[1]);
            } else {
                throw new IllegalArgumentException("Label field format error");
            }
        }
        names = res;
    }

    public boolean matchLabel(Label label) {
        if (label == null || label.names.isEmpty()) {
            return false;
        }
        for (Map.Entry<String, String> entry : label.names.entrySet()) {
            if (!names.containsKey(entry.getKey()) || !Objects.equals(names.get(entry.getKey()), entry.getValue())) {
                return false;
            }
        }
        return true;
    }

}

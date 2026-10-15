/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: parse topology template file
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.loader;

import com.alibaba.fastjson2.JSONReader;
import com.alibaba.fastjson2.reader.ObjectReader;
import com.huawei.umdk.snc.route.topo.template.model.AddrType;
import com.huawei.umdk.snc.route.topo.template.model.Label;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

public final class Deserializers {
    private Deserializers() {}

    abstract static class ListObjectReader<T> implements ObjectReader<List<T>> {
        @Override
        @SuppressWarnings("unchecked")
        public List<T> readObject(JSONReader jsonReader, Type type, Object o, long l) {
            List<String> value = jsonReader.readArray(String.class);
            List<T> res = new ArrayList<>();
            if (value == null || value.isEmpty()) {
                return res;
            }
            for (String s : value) {
                T item = itemParser(s);
                if (item != null) {
                    res.add(item);
                }
            }
            return res;
        }

        abstract T itemParser(String s);
    }

    static class LabelListReader extends ListObjectReader<Label> implements ObjectReader<List<Label>> {
        @Override
        Label itemParser(String s) {
            Label label = new Label();
            if (s != null && !s.isEmpty()) {
                label.refreshAllNames(s);
            }
            return label;
        }
    }

    static class HexLongReader implements ObjectReader<Long> {
        @Override
        public Long readObject(JSONReader jsonReader, Type type, Object o, long l) {
            String value = jsonReader.readString();
            if (value == null || value.isEmpty()) {
                throw new IllegalArgumentException("hex long value is null or empty");
            }
            return Long.decode(value);
        }
    }

    static class AddrTypeListReader extends ListObjectReader<AddrType> implements ObjectReader<List<AddrType>> {
        @Override
        AddrType itemParser(String s) {
            return AddrType.getAddrType(s);
        }
    }
}

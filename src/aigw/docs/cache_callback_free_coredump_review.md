# 缓存回调接口 Free Coredump 问题检视报告

## 问题描述

在联调过程中出现 free coredump 问题，步骤如下：
1. 上层出现异常
2. AIGW 原生库调用缓存回调处理错误
3. 在错误处理过程中，AIGW 试图释放内存
4. 释放的内存地址已损坏（double-free 或 use-after-free）
5. free() 函数访问无效地址导致崩溃

---

## 代码架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Java (DcsCacheDriver)                     │
│                  staticCacheCallback()                       │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ JNI 调用
                              │
┌─────────────────────────────────────────────────────────────┐
│         com_huawei_smartrouter_jni_AigwNative.c              │
│   hash_get_all_callback()                                    │
│   hash_get_all_batch_callback()                              │
│   hash_set_fields_callback()                                 │
│   hash_delete_fields_callback()                              │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ C 回调调用
                              │
┌─────────────────────────────────────────────────────────────┐
│                    libaigw.so (Go CGO)                       │
│   GoHashGetAll()                                             │
│   GoHashGetAllBatch()                                        │
│   GoHashSetFields()                                          │
│   GoHashDeleteFields()                                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 严重问题列表

### 问题 1: GoHashGetAllBatch 中 C.malloc 未初始化内存 ⚠️ **最可能导致 coredump**

**文件**: `src/libaigw.go:447-451`

**代码**:
```go
outArrays := (*C.key_value_array_t)(C.malloc(C.size_t(unsafe.Sizeof(C.key_value_array_t{})) * C.size_t(arrayCount)))
if outArrays == nil {
    return nil, base.AIGW_ERR_NO_MEMORY
}
defer C.free(unsafe.Pointer(outArrays))
```

**问题分析**:
- `C.malloc` 分配的内存**未初始化**，包含垃圾值
- 每个 `outArrays[i].pairs` 初始值是随机的垃圾指针
- 如果 C 回调失败或部分失败，`outArrays[i].pairs` 仍是垃圾值
- 后续 Go 侧检查 `pairs != nil` 并尝试 `free()` → **coredump**

**触发条件**:
- Java 回调返回 null
- Java 回调返回 status != 0
- Java 回调抛出异常
- 网络超时/连接失败

---

### 问题 2: hash_get_all_batch_callback 未初始化 out_arrays

**文件**: `com_huawei_smartrouter_jni_AigwNative.c:559-692`

**代码 (第 583-585 行)**:
```c
if (result == NULL) {
    return AIGW_ERR_INTERNAL;  // ⚠️ out_arrays 未初始化！
}
```

**代码 (第 612-615 行)**:
```c
if (status != 0) {
    (*env)->DeleteLocalRef(env, result);
    return AIGW_SUCCESS;  // ⚠️ out_arrays 未初始化！返回 SUCCESS！
}
```

**问题分析**:
- 当 Java 返回 null 或 status != 0 时
- `out_arrays` 数组没有被初始化（pairs 仍是垃圾值）
- 函数返回错误码，但 Go 侧不知道哪些元素需要释放
- Go 侧的 `defer` 会尝试 `free(垃圾值)` → **coredump**

**特别严重**: 第 614 行返回 `AIGW_SUCCESS` 但 `out_arrays` 未初始化！

---

### 问题 3: hash_get_all_batch_callback 循环中 malloc 失败不清理已分配内存

**文件**: `com_huawei_smartrouter_jni_AigwNative.c:652-657`

**代码**:
```c
out_arrays[i].pairs = (key_value_pair_t*)malloc(sizeof(key_value_pair_t) * pairsLen);
if (out_arrays[i].pairs == NULL) {
    out_arrays[i].count = 0;
    (*env)->DeleteLocalRef(env, pairs);
    continue;  // ⚠️ 前面已分配的 out_arrays[0..i-1].pairs 没有清理！
}
```

**问题分析**:
- 循环中第 i 个 malloc 失败时只是 continue
- 前面 `out_arrays[0..i-1].pairs` 已经分配了内存
- 这些内存不会被释放 → **内存泄漏**
- 如果 Go 侧后续处理出错，可能导致悬空指针

---

### 问题 4: GoHashGetAllBatch 错误返回时不清理已分配的 pairs

**文件**: `src/libaigw.go:460-462`

**代码**:
```go
result := make([]map[string]string, 0, arrayCount)
if cErr != C.AIGW_SUCCESS {
    return result, c2goError(cErr)  // ⚠️ 没有清理 outArrays 中可能已分配的 pairs！
}
```

**问题分析**:
- 当 C 回调返回错误时直接返回
- 但 C 回调可能已经部分填充了 `outArrays[i].pairs`
- 这些已分配的内存不会被释放 → **内存泄漏**
- `defer C.free(unsafe.Pointer(outArrays))` 只释放外层数组，不释放内部的 pairs

---

### 问题 5: GoHashGetAll 无条件 defer free

**文件**: `src/libaigw.go:492-493`

**代码**:
```go
cErr := C.call_hash_get_all(cKey, &outMap)
defer C.free(unsafe.Pointer(outMap.pairs))  // ⚠️ 无条件执行
```

**问题分析**:
- `outMap` 是栈变量，`outMap.pairs` 初始值未定义
- 如果 C 回调失败且**没有设置 `pairs = NULL`**，`defer free()` 会释放垃圾值
- 当前上层 C 回调 `hash_get_all_callback` 在错误路径都设置了 `pairs = NULL`，所以暂时安全
- 但如果上层实现变化，可能导致 **coredump**

---

### 问题 6: hash_get_all_callback 错误路径返回 AIGW_SUCCESS

**文件**: `com_huawei_smartrouter_jni_AigwNative.c:386-430`

**代码**:
```c
if (result == NULL) {
    out_array->pairs = NULL;
    out_array->count = 0;
    return AIGW_SUCCESS;  // ⚠️ 返回 SUCCESS？
}

if (status != 0) {
    out_array->pairs = NULL;
    out_array->count = 0;
    (*env)->DeleteLocalRef(env, result);
    return AIGW_SUCCESS;  // ⚠️ status != 0 应该是错误，返回 SUCCESS？
}
```

**问题分析**:
- Java 返回 null 或 status != 0 应该是错误情况
- 但函数返回 `AIGW_SUCCESS`
- Go 侧会认为操作成功，但实际数据可能不完整
- 可能导致数据不一致问题

---

### 问题 7: hash_set_fields_callback 和 hash_delete_fields_callback 返回值问题

**文件**: `com_huawei_smartrouter_jni_AigwNative.c:523-527, 552-556`

**代码**:
```c
// hash_set_fields_callback
if (result == NULL) {
    return AIGW_ERR_INTERNAL;  // ✓ 正确返回错误
}
return AIGW_SUCCESS;  // ⚠️ 没有检查 Java 返回的 status！

// hash_delete_fields_callback
if (result == NULL) {
    return AIGW_ERR_INTERNAL;  // ✓ 正确返回错误
}
return AIGW_SUCCESS;  // ⚠️ 没有检查 Java 返回的 status！
```

**问题分析**:
- 这两个函数没有解析 Java 返回的 status
- 无论 Java 操作成功还是失败，都返回 `AIGW_SUCCESS`
- 可能导致数据不一致

---

## 崩溃场景汇总

| 场景 | 问题位置 | 原因 | 结果 |
|------|----------|------|------|
| **场景 1** | Go GoHashGetAllBatch | C.malloc 未初始化，C 回调失败后 pairs 是垃圾值 | `free(垃圾值)` → coredump |
| **场景 2** | C hash_get_all_batch_callback | Java 返回 null/status!=0 时未初始化 out_arrays | Go free(垃圾值) → coredump |
| **场景 3** | C hash_get_all_batch_callback | 循环 malloc 失败不清理已分配内存 | 内存泄漏 |
| **场景 4** | Go GoHashGetAllBatch | C 回调失败时不清理已分配的 pairs | 内存泄漏 |
| **场景 5** | Go GoHashGetAll | 如果上层 C 回调未设置 pairs=NULL | `free(垃圾值)` → coredump |
| **场景 6** | C hash_get_all_callback | 错误路径返回 AIGW_SUCCESS | 数据不一致 |

---

## 修复建议

### 修复 1: GoHashGetAllBatch - 初始化内存

**文件**: `src/libaigw.go`

```go
func GoHashGetAllBatch(keys []string) ([]map[string]string, error) {
    if len(keys) == 0 {
        return nil, base.AIGW_ERR_INVALID_PARAM
    }

    cKeys := make([]*C.char, len(keys))
    for i, key := range keys {
        cKeys[i] = C.CString(key)
    }
    defer func() {
        for _, ck := range cKeys {
            C.free(unsafe.Pointer(ck))
        }
    }()

    cKeysPtr := &cKeys[0]
    arrayCount := len(keys)
    outArrays := (*C.key_value_array_t)(C.malloc(C.size_t(unsafe.Sizeof(C.key_value_array_t{})) * C.size_t(arrayCount)))
    if outArrays == nil {
        return nil, base.AIGW_ERR_NO_MEMORY
    }

    // ✅ 关键修复：初始化所有元素
    arraySlice := unsafe.Slice(outArrays, int(arrayCount))
    for i := 0; i < int(arrayCount); i++ {
        arraySlice[i].pairs = nil
        arraySlice[i].count = 0
        arraySlice[i].ttl = 0
    }

    // ✅ 使用 defer 确保清理所有可能分配的 pairs
    defer func() {
        for i := 0; i < int(arrayCount); i++ {
            if arraySlice[i].pairs != nil {
                C.free(unsafe.Pointer(arraySlice[i].pairs))
            }
        }
        C.free(unsafe.Pointer(outArrays))
    }()

    cErr := C.call_hash_get_all_batch(
        (**C.char)(unsafe.Pointer(cKeysPtr)),
        C.uint32_t(len(keys)),
        outArrays,
    )

    if cErr != C.AIGW_SUCCESS {
        return nil, c2goError(cErr)
    }

    result := make([]map[string]string, 0, arrayCount)
    for i := 0; i < int(arrayCount); i++ {
        outMap := make(map[string]string, int(arraySlice[i].count))
        if arraySlice[i].count > 0 && arraySlice[i].pairs != nil {
            pairSlice := unsafe.Slice(arraySlice[i].pairs, int(arraySlice[i].count))
            for j := 0; j < int(arraySlice[i].count); j++ {
                pair := pairSlice[j]
                k := C.GoString(&pair.key[0])
                v := C.GoString(&pair.value[0])
                outMap[k] = v
            }
        }
        // ✅ 已分配的 pairs 会在 defer 中释放，这里置 nil 避免重复释放
        arraySlice[i].pairs = nil
        result = append(result, outMap)
    }

    return result, nil
}
```

### 修复 2: GoHashGetAll - 条件性 defer

**文件**: `src/libaigw.go`

```go
func GoHashGetAll(key string) (map[string]string, error) {
    cKey := C.CString(key)
    defer C.free(unsafe.Pointer(cKey))

    var outMap C.key_value_array_t
    // ✅ 显式初始化
    outMap.pairs = nil
    outMap.count = 0

    cErr := C.call_hash_get_all(cKey, &outMap)

    // ✅ 只在成功且 pairs 非空时释放
    if cErr == C.AIGW_SUCCESS && outMap.pairs != nil {
        defer C.free(unsafe.Pointer(outMap.pairs))
    }

    if cErr != C.AIGW_SUCCESS {
        return nil, c2goError(cErr)
    }

    result := make(map[string]string, int(outMap.count))
    if outMap.count > 0 {
        pairs := unsafe.Slice(outMap.pairs, int(outMap.count))
        for i := 0; i < int(outMap.count); i++ {
            pair := pairs[i]
            k := C.GoString(&pair.key[0])
            v := C.GoString(&pair.value[0])
            result[k] = v
        }
    }
    return result, nil
}
```

### 修复 3: hash_get_all_batch_callback - 初始化和错误处理

**文件**: `com_huawei_smartrouter_jni_AigwNative.c`

```c
static aigw_error_t hash_get_all_batch_callback(const char **keys, uint32_t key_count, key_value_array_t *out_arrays) {
    JNIEnv *env = getJNIEnv();
    if (env == NULL) {
        // ✅ 初始化 out_arrays
        for (uint32_t i = 0; i < key_count; i++) {
            out_arrays[i].pairs = NULL;
            out_arrays[i].count = 0;
        }
        return AIGW_ERR_INTERNAL;
    }

    if (g_staticCacheCallbackMethodID == NULL || g_stringClass == NULL) {
        // ✅ 初始化 out_arrays
        for (uint32_t i = 0; i < key_count; i++) {
            out_arrays[i].pairs = NULL;
            out_arrays[i].count = 0;
        }
        return AIGW_ERR_INTERNAL;
    }

    // ... 创建 jkeys ...

    jobjectArray result = (jobjectArray)(*env)->CallStaticObjectMethod(...);

    if (result == NULL) {
        // ✅ 初始化 out_arrays
        for (uint32_t i = 0; i < key_count; i++) {
            out_arrays[i].pairs = NULL;
            out_arrays[i].count = 0;
        }
        return AIGW_ERR_INTERNAL;
    }

    // ... 获取 status ...

    if (status != 0) {
        (*env)->DeleteLocalRef(env, result);
        // ✅ 初始化 out_arrays
        for (uint32_t i = 0; i < key_count; i++) {
            out_arrays[i].pairs = NULL;
            out_arrays[i].count = 0;
        }
        // ✅ 应该返回错误码
        return AIGW_ERR_INTERNAL;  // 不是 AIGW_SUCCESS
    }

    // ... 处理结果，添加错误处理 ...

    // ✅ 在循环中 malloc 失败时，需要清理已分配的内存并返回错误
    // 或者标记失败但继续处理其他元素
}
```

### 修复 4: hash_get_all_callback - 返回正确的错误码

**文件**: `com_huawei_smartrouter_jni_AigwNative.c`

```c
static aigw_error_t hash_get_all_callback(const char *key, key_value_array_t *out_array) {
    // ... 前面代码 ...

    if (result == NULL) {
        out_array->pairs = NULL;
        out_array->count = 0;
        return AIGW_ERR_NOT_FOUND;  // ✅ 返回正确的错误码
    }

    // ...

    if (status != 0) {
        out_array->pairs = NULL;
        out_array->count = 0;
        (*env)->DeleteLocalRef(env, result);
        return AIGW_ERR_INTERNAL;  // ✅ 返回错误码
    }

    // ...
}
```

### 修复 5: hash_set_fields_callback 和 hash_delete_fields_callback

**文件**: `com_huawei_smartrouter_jni_AigwNative.c`

```c
static aigw_error_t hash_set_fields_callback(const char *key, const key_value_array_t *fields) {
    // ... 现有代码 ...

    jobjectArray result = (jobjectArray)(*env)->CallStaticObjectMethod(...);

    if (result == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    // ✅ 添加：检查 Java 返回的 status
    jsize resultLen = (*env)->GetArrayLength(env, result);
    if (resultLen >= 1) {
        jobject jstatus = (*env)->GetObjectArrayElement(env, result, 0);
        if (jstatus != NULL) {
            jclass statusClass = (*env)->GetObjectClass(env, jstatus);
            jmethodID intValueMethod = (*env)->GetMethodID(env, statusClass, "intValue", "()I");
            if (intValueMethod != NULL) {
                jint status = (*env)->CallIntMethod(env, jstatus, intValueMethod);
                (*env)->DeleteLocalRef(env, jstatus);
                (*env)->DeleteLocalRef(env, result);
                if (status != 0) {
                    return AIGW_ERR_INTERNAL;
                }
            }
        }
    }

    (*env)->DeleteLocalRef(env, result);
    return AIGW_SUCCESS;
}
```

---

## 内存管理契约总结

根据 `include/aigw.h` 的定义，回调函数必须遵循以下契约：

| 回调函数 | 分配责任 | 释放责任 | 错误处理要求 |
|----------|----------|----------|--------------|
| `hash_get_all` | C 回调分配 `out_array->pairs` | Go 侧释放 | 错误时必须设置 `pairs = NULL, count = 0` |
| `hash_get_all_batch` | C 回调分配每个 `out_arrays[i].pairs` | Go 侧释放每个 | 错误时必须初始化所有元素为 `pairs = NULL, count = 0` |
| `hash_set_fields` | 无 | 无 | 返回错误码表示失败 |
| `hash_delete_fields` | 无 | 无 | 返回错误码表示失败 |

**关键原则**:
1. **谁分配谁释放**：C 回调用 `malloc` 分配，Go 侧用 `C.free` 释放
2. **错误路径必须初始化**：出错时必须将指针设为 NULL
3. **批量操作必须完整初始化**：`hash_get_all_batch` 必须初始化所有数组元素
4. **返回值必须正确**：失败返回错误码，不是 AIGW_SUCCESS

---

## 检视结论

**最可能导致 free coredump 的问题是**：

1. **GoHashGetAllBatch 中 C.malloc 未初始化**（问题 1）
   - 当 Java 回调失败时，Go 侧尝试 free(垃圾值)
   - 这是崩溃的最可能原因

2. **hash_get_all_batch_callback 在错误路径未初始化 out_arrays**（问题 2）
   - Java 返回 null 或 status != 0 时
   - 函数返回但 out_arrays 包含垃圾值
   - Go 侧 free(垃圾值) → coredump

3. **hash_get_all_batch_callback status != 0 时返回 AIGW_SUCCESS**（问题 2 的一部分）
   - 错误情况返回成功
   - Go 侧误以为操作成功，尝试处理垃圾数据

**建议优先修复顺序**：
1. 修复 1 和修复 2（Go 侧初始化和条件释放）
2. 修复 3（C 侧初始化和错误处理）
3. 修复 4 和修复 5（C 侧返回正确错误码）

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * JNI Implementation for AIGW Native Library
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include "aigw.h"
#include "securec.h"

// Global JVM reference for callbacks
static JavaVM *g_jvm = NULL;

// Thread-local storage for attached threads
static pthread_key_t g_tls_key;
static pthread_once_t g_tls_init_once = PTHREAD_ONCE_INIT;

// TLS cleanup function
static void tls_cleanup(void *ptr)
{
    // No cleanup needed
}

// Initialize TLS key
static void init_tls_key()
{
    pthread_key_create(&g_tls_key, tls_cleanup);
}

// Cached global class reference and method ID (initialized in JNI_OnLoad)
static jclass g_dcsCacheDriverClass = NULL;
static jmethodID g_staticCacheCallbackMethodID = NULL;

// Cached class references for array creation (initialized in JNI_OnLoad)
static jclass g_objectArrayClass = NULL;
static jclass g_stringClass = NULL;

// Java callback result array layout: result[0] = status, result[1..] = payload
#define CB_RESULT_MIN_LEN    2 // minimum entries: [status, payload]
#define CB_RESULT_IDX_STATUS 0
#define CB_RESULT_IDX_PAIRS  1
// Interleaved key/value storage: key at 2*i, value at 2*i+1
#define KV_INTERLEAVE_STRIDE 2

// Helper function to get JNI environment
static JNIEnv* getJNIEnv()
{
    JNIEnv *env = NULL;
    if (g_jvm == NULL) {
        return NULL;
    }
    jint result = (*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_8);
    if (result == JNI_EDETACHED) {
        // Thread is not attached, attach it
        result = (*g_jvm)->AttachCurrentThread(g_jvm, (void**)&env, NULL);
        if (result != JNI_OK) {
            return NULL;
        }
    } else if (result != JNI_OK) {
        return NULL;
    }
    return env;
}

// Helper function to convert Java string to C string
static char* jstringToCStr(JNIEnv *env, jstring jstr)
{
    if (jstr == NULL) {
        return NULL;
    }
    const char *cstr = (*env)->GetStringUTFChars(env, jstr, NULL);
    if (cstr == NULL) {
        return NULL;
    }
    char *result = strdup(cstr);
    (*env)->ReleaseStringUTFChars(env, jstr, cstr);
    return result;
}

// Helper function to create Java string from C string
static jstring cStrToJString(JNIEnv *env, const char *cstr)
{
    if (cstr == NULL) {
        return NULL;
    }
    return (*env)->NewStringUTF(env, cstr);
}

// Helper function to convert Java config to C structure
static aigw_config_t* convertAigwConfig(JNIEnv *env, jobject jconfig)
{
    if (jconfig == NULL) {
        return NULL;
    }

    aigw_config_t *config = (aigw_config_t*)malloc(sizeof(aigw_config_t));
    if (config == NULL) {
        return NULL;
    }

    jclass cls = (*env)->GetObjectClass(env, jconfig);

    jfieldID logLevelField = (*env)->GetFieldID(env, cls, "logLevel", "Ljava/lang/String;");
    jstring jlogLevel = (jstring)(*env)->GetObjectField(env, jconfig, logLevelField);
    config->log_level = jstringToCStr(env, jlogLevel);
    (*env)->DeleteLocalRef(env, jlogLevel);

    jfieldID logPathField = (*env)->GetFieldID(env, cls, "logPath", "Ljava/lang/String;");
    jstring jlogPath = (jstring)(*env)->GetObjectField(env, jconfig, logPathField);
    config->log_path = jstringToCStr(env, jlogPath);
    (*env)->DeleteLocalRef(env, jlogPath);

    jfieldID maxInstancesField = (*env)->GetFieldID(env, cls, "maxInstancesPerModel", "I");
    config->max_instances_per_model = (*env)->GetIntField(env, jconfig, maxInstancesField);

    jfieldID maxModelsField = (*env)->GetFieldID(env, cls, "maxSupportedModels", "I");
    config->max_supported_models = (*env)->GetIntField(env, jconfig, maxModelsField);

    jfieldID maxPromptField = (*env)->GetFieldID(env, cls, "maxPromptLength", "I");
    config->max_prompt_length = (*env)->GetIntField(env, jconfig, maxPromptField);

    jfieldID ttlField = (*env)->GetFieldID(env, cls, "requestTtlSeconds", "I");
    config->request_ttl_seconds = (*env)->GetIntField(env, jconfig, ttlField);

    (*env)->DeleteLocalRef(env, cls);
    return config;
}

// Helper function to free aigw_config_t
static void freeAigwConfig(aigw_config_t *config)
{
    if (config == NULL) {
        return;
    }
    if (config->log_level) free((void*)config->log_level);
    if (config->log_path) free((void*)config->log_path);
    free(config);
}

// Find a class by name and create a global ref. Returns NULL on failure.
static jclass load_global_class(JNIEnv *env, const char *name)
{
    jclass localClass = (*env)->FindClass(env, name);
    if (localClass == NULL) {
        return NULL;
    }
    jclass globalRef = (*env)->NewGlobalRef(env, localClass);
    (*env)->DeleteLocalRef(env, localClass);
    return globalRef;
}

// JNI_OnLoad - called when library is loaded
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_ERR;
    }

    g_jvm = vm;

    // Cache DcsCacheDriver class reference
    g_dcsCacheDriverClass = load_global_class(env, "com/huawei/smartrouter/dcs/DcsCacheDriver");
    if (g_dcsCacheDriverClass == NULL) {
        return JNI_ERR;
    }

    // Cache staticCacheCallback method ID
    g_staticCacheCallbackMethodID = (*env)->GetStaticMethodID(env, g_dcsCacheDriverClass, "staticCacheCallback",
        "(ILjava/lang/String;[Ljava/lang/Object;[Ljava/lang/String;I)[Ljava/lang/Object;");
    if (g_staticCacheCallbackMethodID == NULL) {
        (*env)->DeleteGlobalRef(env, g_dcsCacheDriverClass);
        g_dcsCacheDriverClass = NULL;
        return JNI_ERR;
    }

    // Cache Object[] class reference for array creation
    g_objectArrayClass = load_global_class(env, "[Ljava/lang/Object;");
    if (g_objectArrayClass == NULL) {
        (*env)->DeleteGlobalRef(env, g_dcsCacheDriverClass);
        g_dcsCacheDriverClass = NULL;
        return JNI_ERR;
    }

    // Cache String class reference for array creation
    g_stringClass = load_global_class(env, "java/lang/String");
    if (g_stringClass == NULL) {
        (*env)->DeleteGlobalRef(env, g_dcsCacheDriverClass);
        g_dcsCacheDriverClass = NULL;
        (*env)->DeleteGlobalRef(env, g_objectArrayClass);
        g_objectArrayClass = NULL;
        return JNI_ERR;
    }

    return JNI_VERSION_1_8;
}

// JNI_OnUnload - called when library is unloaded
JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) == JNI_OK) {
        if (g_dcsCacheDriverClass != NULL) {
            (*env)->DeleteGlobalRef(env, g_dcsCacheDriverClass);
            g_dcsCacheDriverClass = NULL;
        }
        if (g_objectArrayClass != NULL) {
            (*env)->DeleteGlobalRef(env, g_objectArrayClass);
            g_objectArrayClass = NULL;
        }
        if (g_stringClass != NULL) {
            (*env)->DeleteGlobalRef(env, g_stringClass);
            g_stringClass = NULL;
        }
    }
    g_staticCacheCallbackMethodID = NULL;
    g_jvm = NULL;
}

// Implement: aigwInit
JNIEXPORT jint JNICALL Java_com_huawei_smartrouter_jni_AigwNative_aigwInit(JNIEnv *env, jobject obj, jobject jconfig)
{
    aigw_config_t *config = convertAigwConfig(env, jconfig);
    if (config == NULL) {
        return AIGW_ERR_INVALID_PARAM;
    }

    aigw_error_t result = aigw_init(config);
    freeAigwConfig(config);

    return result;
}

// Implement: aigwUninit
JNIEXPORT void JNICALL Java_com_huawei_smartrouter_jni_AigwNative_aigwUninit(JNIEnv *env, jobject obj)
{
    aigw_uninit();
}

// Fill an aigw_openai_message_t array from a Java AigwNativeMessage[] array.
static void fill_messages_from_java(JNIEnv *env, jobjectArray jmessages, jsize msgCount,
    aigw_openai_message_t *messages)
{
    for (int i = 0; i < msgCount; i++) {
        jobject jmsg = (*env)->GetObjectArrayElement(env, jmessages, i);
        jclass msgCls = (*env)->GetObjectClass(env, jmsg);

        jfieldID roleField = (*env)->GetFieldID(env, msgCls, "role", "Ljava/lang/String;");
        jstring jrole = (jstring)(*env)->GetObjectField(env, jmsg, roleField);
        messages[i].role = jstringToCStr(env, jrole);

        jfieldID contentField = (*env)->GetFieldID(env, msgCls, "content", "Ljava/lang/String;");
        jstring jcontent = (jstring)(*env)->GetObjectField(env, jmsg, contentField);
        messages[i].content = jstringToCStr(env, jcontent);

        (*env)->DeleteLocalRef(env, jmsg);
        (*env)->DeleteLocalRef(env, msgCls);
        (*env)->DeleteLocalRef(env, jrole);
        (*env)->DeleteLocalRef(env, jcontent);
    }
}

// Fill an aigw_node_info_t array from a Java AigwNativeNodeInfo[] array.
static void fill_nodes_from_java(JNIEnv *env, jobjectArray jnodeList, int nodeNum,
    aigw_node_info_t *nodeList)
{
    for (int i = 0; i < nodeNum; i++) {
        jobject jnode = (*env)->GetObjectArrayElement(env, jnodeList, i);
        jclass nodeCls = (*env)->GetObjectClass(env, jnode);

        jfieldID roleField = (*env)->GetFieldID(env, nodeCls, "role", "I");
        nodeList[i].role = (*env)->GetIntField(env, jnode, roleField);

        jfieldID nodeAddrField = (*env)->GetFieldID(env, nodeCls, "nodeAddr", "Ljava/lang/String;");
        jstring jnodeAddr = (jstring)(*env)->GetObjectField(env, jnode, nodeAddrField);
        nodeList[i].node_addr = jstringToCStr(env, jnodeAddr);

        jfieldID groupIdField = (*env)->GetFieldID(env, nodeCls, "groupId", "Ljava/lang/String;");
        jstring jgroupId = (jstring)(*env)->GetObjectField(env, jnode, groupIdField);
        nodeList[i].group_id = jstringToCStr(env, jgroupId);

        (*env)->DeleteLocalRef(env, jnode);
        (*env)->DeleteLocalRef(env, nodeCls);
        (*env)->DeleteLocalRef(env, jnodeAddr);
        (*env)->DeleteLocalRef(env, jgroupId);
    }
}

// Write select result fields back onto the Java result object.
static void write_select_result_to_java(JNIEnv *env, jobject joutResult,
    const aigw_select_result_t *result, aigw_error_t ret)
{
    jclass resultCls = (*env)->GetObjectClass(env, joutResult);
    if (ret == AIGW_SUCCESS) {
        jfieldID prefillField = (*env)->GetFieldID(env, resultCls, "prefillNodeAddr", "Ljava/lang/String;");
        jstring jprefill = cStrToJString(env, result->prefill_node_addr);
        (*env)->SetObjectField(env, joutResult, prefillField, jprefill);

        jfieldID decodeField = (*env)->GetFieldID(env, resultCls, "decodeNodeAddr", "Ljava/lang/String;");
        jstring jdecode = cStrToJString(env, result->decode_node_addr);
        (*env)->SetObjectField(env, joutResult, decodeField, jdecode);

        (*env)->DeleteLocalRef(env, jprefill);
        (*env)->DeleteLocalRef(env, jdecode);
    } else {
        jfieldID errorField = (*env)->GetFieldID(env, resultCls, "errorDesc", "Ljava/lang/String;");
        jstring jerror = cStrToJString(env, result->error_desc);
        (*env)->SetObjectField(env, joutResult, errorField, jerror);
        (*env)->DeleteLocalRef(env, jerror);
    }
    (*env)->DeleteLocalRef(env, resultCls);
}

// Implement: aigwSelectNodes
JNIEXPORT jint JNICALL Java_com_huawei_smartrouter_jni_AigwNative_aigwSelectNodes(JNIEnv *env, jobject obj,
    jobject jrequest, jobject jcontext, jobject joutResult)
{
    aigw_request_t request;
    jclass reqCls = (*env)->GetObjectClass(env, jrequest);

    jfieldID uuidField = (*env)->GetFieldID(env, reqCls, "uuid", "Ljava/lang/String;");
    jstring juuid = (jstring)(*env)->GetObjectField(env, jrequest, uuidField);
    request.uuid = jstringToCStr(env, juuid);

    jfieldID modelField = (*env)->GetFieldID(env, reqCls, "model", "Ljava/lang/String;");
    jstring jmodel = (jstring)(*env)->GetObjectField(env, jrequest, modelField);
    request.model = jstringToCStr(env, jmodel);

    jfieldID messagesField = (*env)->GetFieldID(env, reqCls, "messages",
        "[Lcom/huawei/smartrouter/model/AigwNativeMessage;");
    jobjectArray jmessages = (jobjectArray)(*env)->GetObjectField(env, jrequest, messagesField);
    if (jmessages == NULL) {
        (*env)->DeleteLocalRef(env, reqCls);
        free((void*)request.uuid);
        free((void*)request.model);
        return AIGW_ERR_INVALID_PARAM;
    }
    jsize msgCount = (*env)->GetArrayLength(env, jmessages);
    request.message_num = msgCount;
    if (msgCount <= 0) {
        (*env)->DeleteLocalRef(env, reqCls);
        (*env)->DeleteLocalRef(env, jmessages);
        free((void*)request.uuid);
        free((void*)request.model);
        return AIGW_ERR_INVALID_PARAM;
    }

    aigw_openai_message_t *messages = (aigw_openai_message_t*)malloc(sizeof(aigw_openai_message_t) * msgCount);
    if (messages == NULL) {
        (*env)->DeleteLocalRef(env, reqCls);
        (*env)->DeleteLocalRef(env, jmessages);
        free((void*)request.uuid);
        free((void*)request.model);
        return AIGW_ERR_NO_MEMORY;
    }
    memset(messages, 0, sizeof(aigw_openai_message_t) * msgCount);
    fill_messages_from_java(env, jmessages, msgCount, messages);
    request.messages = messages;

    aigw_select_context_t context;
    jclass ctxCls = (*env)->GetObjectClass(env, jcontext);

    jfieldID nodeNumField = (*env)->GetFieldID(env, ctxCls, "nodeNum", "I");
    context.node_num = (*env)->GetIntField(env, jcontext, nodeNumField);

    jfieldID nodeListField = (*env)->GetFieldID(env, ctxCls, "nodeList",
        "[Lcom/huawei/smartrouter/model/AigwNativeNodeInfo;");
    jobjectArray jnodeList = (jobjectArray)(*env)->GetObjectField(env, jcontext, nodeListField);
    if (jnodeList == NULL) {
        (*env)->DeleteLocalRef(env, ctxCls);
        (*env)->DeleteLocalRef(env, reqCls);
        (*env)->DeleteLocalRef(env, jmessages);
        free((void*)request.uuid);
        free((void*)request.model);
        for (int i = 0; i < msgCount; i++) {
            free((void*)messages[i].role);
            free((void*)messages[i].content);
        }
        free(messages);
        return AIGW_ERR_INVALID_PARAM;
    }

    aigw_node_info_t *nodeList = (aigw_node_info_t*)malloc(sizeof(aigw_node_info_t) * context.node_num);
    if (nodeList == NULL) {
        (*env)->DeleteLocalRef(env, ctxCls);
        (*env)->DeleteLocalRef(env, reqCls);
        (*env)->DeleteLocalRef(env, jmessages);
        (*env)->DeleteLocalRef(env, jnodeList);
        free((void*)request.uuid);
        free((void*)request.model);
        for (int i = 0; i < msgCount; i++) {
            free((void*)messages[i].role);
            free((void*)messages[i].content);
        }
        free(messages);
        return AIGW_ERR_NO_MEMORY;
    }
    memset(nodeList, 0, sizeof(aigw_node_info_t) * context.node_num);
    fill_nodes_from_java(env, jnodeList, context.node_num, nodeList);
    context.node_list = nodeList;

    aigw_select_result_t result;
    memset_s(&result, sizeof(result), 0, sizeof(result));

    aigw_error_t ret = aigw_select_nodes(&request, &context, &result);
    if (ret == AIGW_SUCCESS) {
        write_select_result_to_java(env, joutResult, &result, ret);
    } else {
        write_select_result_to_java(env, joutResult, &result, ret);
    }

    (*env)->DeleteLocalRef(env, ctxCls);
    (*env)->DeleteLocalRef(env, reqCls);
    (*env)->DeleteLocalRef(env, jmessages);
    (*env)->DeleteLocalRef(env, jnodeList);

    free((void*)request.uuid);
    free((void*)request.model);
    for (int i = 0; i < msgCount; i++) {
        free((void*)messages[i].role);
        free((void*)messages[i].content);
    }
    free(messages);
    for (int i = 0; i < context.node_num; i++) {
        free((void*)nodeList[i].node_addr);
        free((void*)nodeList[i].group_id);
    }
    free(nodeList);

    return ret;
}

// Implement: aigwNotifyEvent
JNIEXPORT jint JNICALL Java_com_huawei_smartrouter_jni_AigwNative_aigwNotifyEvent(JNIEnv *env, jobject obj,
    jint eventType, jobject jevent)
{
    aigw_event_info_t event;
    jclass eventCls = (*env)->GetObjectClass(env, jevent);

    jfieldID modelField = (*env)->GetFieldID(env, eventCls, "model", "Ljava/lang/String;");
    jstring jmodel = (jstring)(*env)->GetObjectField(env, jevent, modelField);
    event.model = jstringToCStr(env, jmodel);
    (*env)->DeleteLocalRef(env, jmodel);

    jfieldID requestIdField = (*env)->GetFieldID(env, eventCls, "requestId", "Ljava/lang/String;");
    jstring jrequestId = (jstring)(*env)->GetObjectField(env, jevent, requestIdField);
    event.request_id = jstringToCStr(env, jrequestId);
    (*env)->DeleteLocalRef(env, jrequestId);

    jfieldID eventNameField = (*env)->GetFieldID(env, eventCls, "eventName", "Ljava/lang/String;");
    jstring jeventName = (jstring)(*env)->GetObjectField(env, jevent, eventNameField);
    event.event_name = jstringToCStr(env, jeventName);
    (*env)->DeleteLocalRef(env, jeventName);

    (*env)->DeleteLocalRef(env, eventCls);

    aigw_error_t result = aigw_notify_event((aigw_event_type_t)eventType, &event);

    free((void*)event.model);
    free((void*)event.request_id);
    free((void*)event.event_name);

    return result;
}

// Copy valid key/value pairs from a Java pair array into a pre-allocated C array.
// Returns the number of valid pairs written (skips NULL entries/fields).
static int copy_pairs_from_java(JNIEnv *env, jobjectArray pairs, jsize pairsLen,
    key_value_pair_t *outPairs)
{
    int validCount = 0;
    for (int i = 0; i < pairsLen; i++) {
        jobjectArray pair = (jobjectArray)(*env)->GetObjectArrayElement(env, pairs, i);
        if (pair == NULL) {
            // Skip this pair if it's NULL
            continue;
        }

        jstring jfkey = (jstring)(*env)->GetObjectArrayElement(env, pair, 0);
        jstring jfvalue = (jstring)(*env)->GetObjectArrayElement(env, pair, 1);
        if (jfkey == NULL || jfvalue == NULL) {
            // Skip if either key or value is NULL
            if (jfkey != NULL) (*env)->DeleteLocalRef(env, jfkey);
            if (jfvalue != NULL) (*env)->DeleteLocalRef(env, jfvalue);
            (*env)->DeleteLocalRef(env, pair);
            continue;
        }

        const char *ckey = (*env)->GetStringUTFChars(env, jfkey, NULL);
        const char *cvalue = (*env)->GetStringUTFChars(env, jfvalue, NULL);

        strncpy_s(outPairs[validCount].key, AIGW_CACHE_KEY_MAX_LEN, ckey, AIGW_CACHE_KEY_MAX_LEN - 1);
        strncpy_s(outPairs[validCount].value, AIGW_CACHE_VALUE_MAX_LEN, cvalue, AIGW_CACHE_VALUE_MAX_LEN - 1);
        validCount++;

        (*env)->ReleaseStringUTFChars(env, jfkey, ckey);
        (*env)->ReleaseStringUTFChars(env, jfvalue, cvalue);
        (*env)->DeleteLocalRef(env, jfkey);
        (*env)->DeleteLocalRef(env, jfvalue);
        (*env)->DeleteLocalRef(env, pair);
    }
    return validCount;
}

// Cache driver callback functions
static aigw_error_t hash_get_all_callback(const char *key, key_value_array_t *out_array)
{
    JNIEnv *env = getJNIEnv();
    if (env == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    // Check if method ID is cached
    if (g_staticCacheCallbackMethodID == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    jstring jkey = cStrToJString(env, key);

    jobjectArray result = (jobjectArray)(*env)->CallStaticObjectMethod(env, g_dcsCacheDriverClass,
        g_staticCacheCallbackMethodID, 1, jkey, NULL, NULL, 0);
    if (result == NULL) {
        out_array->pairs = NULL;
        out_array->count = 0;
        return AIGW_SUCCESS;
    }

    jsize resultLen = (*env)->GetArrayLength(env, result);
    if (resultLen < CB_RESULT_MIN_LEN) {
        out_array->pairs = NULL;
        out_array->count = 0;
        (*env)->DeleteLocalRef(env, result);
        return AIGW_SUCCESS;
    }

    // Get status code from result[0]
    jobject jstatus = (*env)->GetObjectArrayElement(env, result, CB_RESULT_IDX_STATUS);
    if (jstatus == NULL) {
        out_array->pairs = NULL;
        out_array->count = 0;
        (*env)->DeleteLocalRef(env, result);
        return AIGW_SUCCESS;
    }

    jclass statusClass = (*env)->GetObjectClass(env, jstatus);
    jmethodID intValueMethod = (*env)->GetMethodID(env, statusClass, "intValue", "()I");
    if (intValueMethod == NULL) {
        (*env)->DeleteLocalRef(env, jstatus);
        out_array->pairs = NULL;
        out_array->count = 0;
        (*env)->DeleteLocalRef(env, result);
        return AIGW_SUCCESS;
    }

    jint status = (*env)->CallIntMethod(env, jstatus, intValueMethod);
    (*env)->DeleteLocalRef(env, jstatus);

    if (status != 0) {
        out_array->pairs = NULL;
        out_array->count = 0;
        (*env)->DeleteLocalRef(env, result);
        return AIGW_SUCCESS;
    }

    // Get pairs array from result[1]
    jobjectArray pairs = (jobjectArray)(*env)->GetObjectArrayElement(env, result, 1);
    if (pairs == NULL) {
        out_array->pairs = NULL;
        out_array->count = 0;
        (*env)->DeleteLocalRef(env, result);
        return AIGW_SUCCESS;
    }

    jsize pairsLen = (*env)->GetArrayLength(env, pairs);
    if (pairsLen <= 0) {
        out_array->pairs = NULL;
        out_array->count = 0;
        (*env)->DeleteLocalRef(env, pairs);
        (*env)->DeleteLocalRef(env, result);
        return AIGW_SUCCESS;
    }

    out_array->count = pairsLen;
    out_array->pairs = (key_value_pair_t*)malloc(sizeof(key_value_pair_t) * pairsLen);
    if (out_array->pairs == NULL) {
        out_array->count = 0;
        (*env)->DeleteLocalRef(env, pairs);
        (*env)->DeleteLocalRef(env, result);
        return AIGW_ERR_NO_MEMORY;
    }

    int validCount = copy_pairs_from_java(env, pairs, pairsLen, out_array->pairs);
    out_array->count = validCount;

    (*env)->DeleteLocalRef(env, pairs);
    (*env)->DeleteLocalRef(env, result);
    return AIGW_SUCCESS;
}

static aigw_error_t hash_set_fields_callback(const char *key, const key_value_array_t *fields)
{
    JNIEnv *env = getJNIEnv();
    if (env == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    if (g_staticCacheCallbackMethodID == NULL || g_objectArrayClass == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    jstring jkey = cStrToJString(env, key);
    if (jkey == NULL) {
        return AIGW_ERR_NO_MEMORY;
    }

    // Check fields->count is positive
    if (fields->count <= 0) {
        (*env)->DeleteLocalRef(env, jkey);
        return AIGW_ERR_INVALID_PARAM;
    }

    // Create a 1D array with alternating key-value pairs
    // Each pair takes 2 slots: key at even index, value at odd index
    jobjectArray jfields = (*env)->NewObjectArray(env, fields->count * 2, g_stringClass, NULL);
    if (jfields == NULL) {
        (*env)->DeleteLocalRef(env, jkey);
        return AIGW_ERR_NO_MEMORY;
    }

    for (int i = 0; i < fields->count; i++) {
        jstring jfkey = cStrToJString(env, fields->pairs[i].key);
        jstring jfvalue = cStrToJString(env, fields->pairs[i].value);
        if (jfkey == NULL || jfvalue == NULL) {
            if (jfkey != NULL) (*env)->DeleteLocalRef(env, jfkey);
            if (jfvalue != NULL) (*env)->DeleteLocalRef(env, jfvalue);
            (*env)->DeleteLocalRef(env, jfields);
            (*env)->DeleteLocalRef(env, jkey);
            return AIGW_ERR_NO_MEMORY;
        }

        // Store key at index 2*i, value at index 2*i+1
        (*env)->SetObjectArrayElement(env, jfields, KV_INTERLEAVE_STRIDE * i, jfkey);
        (*env)->SetObjectArrayElement(env, jfields, KV_INTERLEAVE_STRIDE * i + 1, jfvalue);

        (*env)->DeleteLocalRef(env, jfkey);
        (*env)->DeleteLocalRef(env, jfvalue);
    }

    jobjectArray result = (jobjectArray)(*env)->CallStaticObjectMethod(env, g_dcsCacheDriverClass,
        g_staticCacheCallbackMethodID, 2, jkey, jfields, NULL, 0);

    // 清理局部引用
    (*env)->DeleteLocalRef(env, jfields);
    (*env)->DeleteLocalRef(env, jkey);

    if (result == NULL) {
        return AIGW_ERR_INTERNAL;
    }
    (*env)->DeleteLocalRef(env, result);

    return AIGW_SUCCESS;
}

// Release local references for array elements in range [0, end)
static void release_array_elements(JNIEnv *env, jobjectArray array, uint32_t end)
{
    for (uint32_t j = 0; j < end; j++) {
        jobject elem = (*env)->GetObjectArrayElement(env, array, j);
        if (elem != NULL) {
            (*env)->DeleteLocalRef(env, elem);
        }
    }
}

static aigw_error_t hash_delete_fields_callback(const char *key, char **field_keys, uint32_t field_count)
{
    JNIEnv *env = getJNIEnv();
    if (env == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    if (g_staticCacheCallbackMethodID == NULL || g_stringClass == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    jstring jkey = cStrToJString(env, key);
    if (jkey == NULL) {
        return AIGW_ERR_NO_MEMORY;
    }

    jobjectArray jfieldKeys = (*env)->NewObjectArray(env, field_count, g_stringClass, NULL);
    if (jfieldKeys == NULL) {
        (*env)->DeleteLocalRef(env, jkey);
        return AIGW_ERR_NO_MEMORY;
    }

    for (uint32_t i = 0; i < field_count; i++) {
        jstring jfieldKey = cStrToJString(env, field_keys[i]);
        if (jfieldKey == NULL) {
            // 清理已创建的元素
            release_array_elements(env, jfieldKeys, i);
            (*env)->DeleteLocalRef(env, jfieldKeys);
            (*env)->DeleteLocalRef(env, jkey);
            return AIGW_ERR_NO_MEMORY;
        }
        (*env)->SetObjectArrayElement(env, jfieldKeys, i, jfieldKey);
        (*env)->DeleteLocalRef(env, jfieldKey);
    }

    jobjectArray result = (jobjectArray)(*env)->CallStaticObjectMethod(env, g_dcsCacheDriverClass,
        g_staticCacheCallbackMethodID, 3, jkey, NULL, jfieldKeys, field_count);

    // 清理局部引用
    (*env)->DeleteLocalRef(env, jfieldKeys);
    (*env)->DeleteLocalRef(env, jkey);

    if (result == NULL) {
        return AIGW_ERR_INTERNAL;
    }
    (*env)->DeleteLocalRef(env, result);

    return AIGW_SUCCESS;
}

static aigw_error_t hash_get_all_batch_callback(const char **keys, uint32_t key_count, key_value_array_t *out_arrays)
{
    JNIEnv *env = getJNIEnv();
    if (env == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    if (g_staticCacheCallbackMethodID == NULL || g_stringClass == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    // Create Java String array for keys
    jobjectArray jkeys = (*env)->NewObjectArray(env, key_count, g_stringClass, NULL);
    if (jkeys == NULL) {
        return AIGW_ERR_NO_MEMORY;
    }

    for (uint32_t i = 0; i < key_count; i++) {
        jstring jkey = cStrToJString(env, keys[i]);
        if (jkey == NULL) {
            // Cleanup already created elements
            for (uint32_t j = 0; j < i; j++) {
                jobject elem = (*env)->GetObjectArrayElement(env, jkeys, j);
                if (elem != NULL) {
                    (*env)->DeleteLocalRef(env, elem);
                }
            }
            (*env)->DeleteLocalRef(env, jkeys);
            return AIGW_ERR_NO_MEMORY;
        }
        (*env)->SetObjectArrayElement(env, jkeys, i, jkey);
        (*env)->DeleteLocalRef(env, jkey);
    }

    jobjectArray result = (jobjectArray)(*env)->CallStaticObjectMethod(env, g_dcsCacheDriverClass,
        g_staticCacheCallbackMethodID, 4, NULL, NULL, jkeys, key_count);
    if (result == NULL) {
        return AIGW_ERR_INTERNAL;
    }

    jsize resultLen = (*env)->GetArrayLength(env, result);
    if (resultLen < CB_RESULT_MIN_LEN) {
        (*env)->DeleteLocalRef(env, result);
        return AIGW_ERR_INTERNAL;
    }

    // Get status code from result[0]
    jobject jstatus = (*env)->GetObjectArrayElement(env, result, CB_RESULT_IDX_STATUS);
    if (jstatus == NULL) {
        (*env)->DeleteLocalRef(env, result);
        return AIGW_ERR_INTERNAL;
    }

    jclass statusClass = (*env)->GetObjectClass(env, jstatus);
    jmethodID intValueMethod = (*env)->GetMethodID(env, statusClass, "intValue", "()I");
    if (intValueMethod == NULL) {
        (*env)->DeleteLocalRef(env, jstatus);
        (*env)->DeleteLocalRef(env, result);
        return AIGW_ERR_INTERNAL;
    }

    jint status = (*env)->CallIntMethod(env, jstatus, intValueMethod);
    (*env)->DeleteLocalRef(env, jstatus);

    if (status != 0) {
        (*env)->DeleteLocalRef(env, result);
        // 清理已分配的内存
        for (uint32_t i = 0; i < key_count; i++) {
            if (out_arrays[i].pairs != NULL) {
                free(out_arrays[i].pairs);
                out_arrays[i].pairs = NULL;
                out_arrays[i].count = 0;
            }
        }
        return AIGW_ERR_INTERNAL;
    }

    // Get batch results array from result[1]
    jobjectArray batchResults = (jobjectArray)(*env)->GetObjectArrayElement(env, result, 1);
    if (batchResults == NULL) {
        (*env)->DeleteLocalRef(env, result);
        return AIGW_ERR_INTERNAL;
    }

    jsize batchResultsLen = (*env)->GetArrayLength(env, batchResults);
    if (batchResultsLen != key_count) {
        (*env)->DeleteLocalRef(env, batchResults);
        (*env)->DeleteLocalRef(env, result);
        return AIGW_ERR_INTERNAL;
    }

    // Process each key's result
    for (uint32_t i = 0; i < key_count; i++) {
        jobjectArray pairs = (jobjectArray)(*env)->GetObjectArrayElement(env, batchResults, i);
        if (pairs == NULL) {
            out_arrays[i].pairs = NULL;
            out_arrays[i].count = 0;
            continue;
        }

        jsize pairsLen = (*env)->GetArrayLength(env, pairs);
        if (pairsLen <= 0) {
            out_arrays[i].pairs = NULL;
            out_arrays[i].count = 0;
            (*env)->DeleteLocalRef(env, pairs);
            continue;
        }

        out_arrays[i].count = pairsLen;
        out_arrays[i].pairs = (key_value_pair_t*)malloc(sizeof(key_value_pair_t) * pairsLen);
        if (out_arrays[i].pairs == NULL) {
            out_arrays[i].count = 0;
            (*env)->DeleteLocalRef(env, pairs);
            continue;
        }

        int validCount = copy_pairs_from_java(env, pairs, pairsLen, out_arrays[i].pairs);
        out_arrays[i].count = validCount;

        (*env)->DeleteLocalRef(env, pairs);
    }

    (*env)->DeleteLocalRef(env, batchResults);
    (*env)->DeleteLocalRef(env, result);
    return AIGW_SUCCESS;
}

// Implement: aigwRegisterCacheDriver
JNIEXPORT jint JNICALL Java_com_huawei_smartrouter_jni_AigwNative_aigwRegisterCacheDriver(JNIEnv *env, jobject obj,
    jobject jdriver)
{
    static aigw_cache_driver_ops_t ops = {
        .hash_get_all = hash_get_all_callback,
        .hash_get_all_batch = hash_get_all_batch_callback,
        .hash_set_fields = hash_set_fields_callback,
        .hash_delete_fields = hash_delete_fields_callback
    };

    aigw_cache_driver_t driver;
    driver.ops = ops;

    jclass driverCls = (*env)->GetObjectClass(env, jdriver);
    jfieldID nameField = (*env)->GetFieldID(env, driverCls, "driverName", "Ljava/lang/String;");
    jstring jname = (jstring)(*env)->GetObjectField(env, jdriver, nameField);
    driver.driver_name = jstringToCStr(env, jname);
    (*env)->DeleteLocalRef(env, jname);
    (*env)->DeleteLocalRef(env, driverCls);

    aigw_error_t result = aigw_register_cache_driver(&driver);

    free((void*)driver.driver_name);

    return result;
}

// Implement: aigwUnregisterCacheDriver
JNIEXPORT jint JNICALL Java_com_huawei_smartrouter_jni_AigwNative_aigwUnregisterCacheDriver(JNIEnv *env, jobject obj)
{
    return aigw_unregister_cache_driver();
}

// Implement: aigwRegisterModel
JNIEXPORT jint JNICALL Java_com_huawei_smartrouter_jni_AigwNative_aigwRegisterModel(JNIEnv *env, jobject obj,
    jobject jconfig)
{
    aigw_model_config_t config;
    jclass configCls = (*env)->GetObjectClass(env, jconfig);

    jfieldID modelField = (*env)->GetFieldID(env, configCls, "model", "Ljava/lang/String;");
    jstring jmodel = (jstring)(*env)->GetObjectField(env, jconfig, modelField);
    config.model = jstringToCStr(env, jmodel);
    (*env)->DeleteLocalRef(env, jmodel);

    jfieldID deployPolicyField = (*env)->GetFieldID(env, configCls, "deployPolicy", "I");
    config.deploy_policy = (*env)->GetIntField(env, jconfig, deployPolicyField);

    jfieldID pLbTypeField = (*env)->GetFieldID(env, configCls, "pLbType", "I");
    config.p_lb_type = (*env)->GetIntField(env, jconfig, pLbTypeField);

    jfieldID dLbTypeField = (*env)->GetFieldID(env, configCls, "dLbType", "I");
    config.d_lb_type = (*env)->GetIntField(env, jconfig, dLbTypeField);

    jfieldID ttftPathField = (*env)->GetFieldID(env, configCls, "pretrainTtftPath", "Ljava/lang/String;");
    jstring jttftPath = (jstring)(*env)->GetObjectField(env, jconfig, ttftPathField);
    config.pretrain_ttft_path = jstringToCStr(env, jttftPath);
    (*env)->DeleteLocalRef(env, jttftPath);

    jfieldID refreshIntervalField = (*env)->GetFieldID(env, configCls, "cacheRefreshIntervalMs", "I");
    config.cache_refresh_interval_ms = (*env)->GetIntField(env, jconfig, refreshIntervalField);

    (*env)->DeleteLocalRef(env, configCls);

    aigw_error_t result = aigw_register_model(&config);

    free((void*)config.model);
    free((void*)config.pretrain_ttft_path);

    return result;
}

// Implement: aigwUnregisterModel
JNIEXPORT jint JNICALL Java_com_huawei_smartrouter_jni_AigwNative_aigwUnregisterModel(JNIEnv *env, jobject obj,
    jstring jmodelName)
{
    char *modelName = jstringToCStr(env, jmodelName);
    aigw_error_t result = aigw_unregister_model(modelName);
    free(modelName);
    (*env)->DeleteLocalRef(env, jmodelName);
    return result;
}

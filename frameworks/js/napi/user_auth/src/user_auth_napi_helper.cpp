/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "user_auth_napi_helper.h"

#include <cinttypes>
#include <uv.h>

#include "securec.h"

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_auth_helper.h"

#define LOG_TAG "USER_AUTH_NAPI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
static constexpr const int MAX_STRING_LENGTH = 65536;
struct DeleteRefHolder {
    napi_env env {nullptr};
    napi_ref ref {nullptr};
};
}

JsRefHolder::JsRefHolder(napi_env env, napi_value value)
{
    if (env == nullptr || value == nullptr) {
        IAM_LOGE("get null ptr");
        return;
    }
    napi_status ret = UserAuthNapiHelper::GetFunctionRef(env, value, ref_);
    if (ret != napi_ok) {
        IAM_LOGE("GetFunctionRef fail %{public}d", ret);
        ref_ = nullptr;
        return;
    }
    env_ = env;
}

JsRefHolder::~JsRefHolder()
{
    if (!IsValid()) {
        IAM_LOGI("invalid");
        return;
    }
    IAM_LOGD("delete reference");
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<DeleteRefHolder> deleteRefHolder = Common::MakeShared<DeleteRefHolder>();
    if (deleteRefHolder == nullptr) {
        IAM_LOGE("deleteRefHolder is null");
        return;
    }
    deleteRefHolder->env = env_;
    deleteRefHolder->ref = ref_;
    auto task = [deleteRefHolder] () {
        IAM_LOGI("start");
        if (deleteRefHolder == nullptr) {
            IAM_LOGE("deleteRefHolder is invalid");
            return;
        }
        napi_status ret = napi_delete_reference(deleteRefHolder->env, deleteRefHolder->ref);
        if (ret != napi_ok) {
            IAM_LOGE("napi_delete_reference fail %{public}d", ret);
            return;
        }
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::JsRefHolder::~JsRefHolder")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

bool JsRefHolder::IsValid() const
{
    return (env_ != nullptr && ref_ != nullptr);
}

napi_ref JsRefHolder::Get() const
{
    return ref_;
}

int32_t UserAuthNapiHelper::GetResultCodeV8(int32_t result)
{
    if (result == CHECK_PERMISSION_FAILED) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED);
    }
    if (result == PIN_EXPIRED) {
        return GENERAL_ERROR;
    }
    if ((result < SUCCESS) || (result > NOT_ENROLLED)) {
        return GENERAL_ERROR;
    }
    return result;
}

int32_t UserAuthNapiHelper::GetResultCodeV9(int32_t result)
{
    if (result == CHECK_PERMISSION_FAILED) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED);
    }
    if (result == INVALID_PARAMETERS) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_INVALID_PARAM);
    }
    if (result == PIN_EXPIRED) {
        return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
    }
    if (result > (INT32_MAX - static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V9_MIN))) {
        return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
    }
    int32_t resultCodeV9 = result + static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V9_MIN);
    if (resultCodeV9 >= static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V9_MIN) &&
        resultCodeV9 <= static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V9_MAX)) {
        return resultCodeV9;
    }
    return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
}

napi_value UserAuthNapiHelper::GenerateBusinessErrorV9(napi_env env, UserAuthResultCode result)
{
    napi_value code;
    std::string msgStr;
    auto res = g_resultV92Str.find(result);
    if (res == g_resultV92Str.end()) {
        IAM_LOGE("result %{public}d not found", static_cast<int32_t>(result));
        msgStr = g_resultV92Str.at(UserAuthResultCode::GENERAL_ERROR);
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR), &code));
    } else {
        msgStr = res->second;
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(result), &code));
    }
    IAM_LOGI("get msg %{public}s", msgStr.c_str());

    napi_value msg;
    NAPI_CALL(env, napi_create_string_utf8(env, msgStr.c_str(), NAPI_AUTO_LENGTH, &msg));

    napi_value businessError;
    NAPI_CALL(env, napi_create_error(env, nullptr, msg, &businessError));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", code));

    return businessError;
}

napi_value UserAuthNapiHelper::GenerateBusinessErrorV21(napi_env env, UserAuthResultCode result)
{
    napi_value code;
    std::string msgStr;
    auto res = g_resultV212Str.find(result);
    if (res == g_resultV212Str.end()) {
        IAM_LOGE("result %{public}d not found", static_cast<int32_t>(result));
        msgStr = g_resultV212Str.at(UserAuthResultCode::GENERAL_ERROR);
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR), &code));
    } else {
        msgStr = res->second;
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(result), &code));
    }
    IAM_LOGI("get msg %{public}s", msgStr.c_str());

    napi_value msg;
    NAPI_CALL(env, napi_create_string_utf8(env, msgStr.c_str(), NAPI_AUTO_LENGTH, &msg));

    napi_value businessError;
    NAPI_CALL(env, napi_create_error(env, nullptr, msg, &businessError));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", code));

    return businessError;
}

napi_value UserAuthNapiHelper::GenerateErrorMsg(napi_env env, UserAuthResultCode result, std::string errorMsg)
{
    napi_value code;
    std::string msgStr;
    auto res = g_resultV92Str.find(result);
    if (res == g_resultV92Str.end()) {
        IAM_LOGE("result %{public}d not found", static_cast<int32_t>(result));
        msgStr = g_resultV92Str.at(UserAuthResultCode::GENERAL_ERROR);
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR), &code));
    } else {
        msgStr = errorMsg;
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(result), &code));
    }
    IAM_LOGI("error msg %{public}s", msgStr.c_str());

    napi_value msg;
    NAPI_CALL(env, napi_create_string_utf8(env, msgStr.c_str(), NAPI_AUTO_LENGTH, &msg));

    napi_value businessError;
    NAPI_CALL(env, napi_create_error(env, nullptr, msg, &businessError));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", code));

    return businessError;
}

UserAuthResultCode UserAuthNapiHelper::ThrowErrorMsg(napi_env env, UserAuthResultCode errorCode, std::string errorMsg)
{
    napi_throw(env, UserAuthNapiHelper::GenerateErrorMsg(env, errorCode, errorMsg));
    return errorCode;
}

napi_status UserAuthNapiHelper::CheckNapiType(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valuetype;
    napi_status result = napi_typeof(env, value, &valuetype);
    if (result != napi_ok) {
        IAM_LOGE("napi_typeof fail");
        return result;
    }
    if (valuetype != type) {
        IAM_LOGE("check valuetype fail");
        return napi_generic_failure;
    }
    return napi_ok;
}

napi_status UserAuthNapiHelper::GetBoolValue(napi_env env, napi_value value, bool &out)
{
    napi_status result = CheckNapiType(env, value, napi_boolean);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    result = napi_get_value_bool(env, value, &out);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_value_bool fail");
    }
    return result;
}

napi_status UserAuthNapiHelper::GetInt32Value(napi_env env, napi_value value, int32_t &out)
{
    napi_status result = CheckNapiType(env, value, napi_number);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    result = napi_get_value_int32(env, value, &out);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_value_int32 fail");
    }
    return result;
}

napi_status UserAuthNapiHelper::GetUint32Value(napi_env env, napi_value value, uint32_t &out)
{
    napi_status result = CheckNapiType(env, value, napi_number);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    result = napi_get_value_uint32(env, value, &out);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_value_uint32 fail");
    }
    return result;
}

napi_status UserAuthNapiHelper::GetStrValue(napi_env env, napi_value value, char *out, size_t &len)
{
    if (out == nullptr) {
        IAM_LOGE("invalid out parameter");
        return napi_invalid_arg;
    }
    napi_status result = CheckNapiType(env, value, napi_string);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    size_t maxLen = len;
    result = napi_get_value_string_utf8(env, value, out, maxLen, &len);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_value_string_utf8 fail");
    }
    if (maxLen > 0) {
        out[maxLen - 1] = '\0';
    }
    return result;
}

napi_status UserAuthNapiHelper::GetFunctionRef(napi_env env, napi_value value, napi_ref &ref)
{
    napi_status result = CheckNapiType(env, value, napi_function);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    result = napi_create_reference(env, value, 1, &ref);
    if (result != napi_ok) {
        IAM_LOGE("napi_create_reference fail");
    }
    return result;
}

napi_status UserAuthNapiHelper::GetUint8ArrayValue(napi_env env, napi_value value,
    size_t limitLen, std::vector<uint8_t> &array)
{
    bool isTypedarray;
    napi_status result = napi_is_typedarray(env, value, &isTypedarray);
    if (result != napi_ok) {
        IAM_LOGE("napi_is_typedarray fail");
        return result;
    }
    if (!isTypedarray) {
        IAM_LOGE("value is not typedarray");
        return napi_array_expected;
    }
    napi_typedarray_type type;
    size_t length;
    void *data;
    napi_value buffer;
    size_t offset;
    result = napi_get_typedarray_info(env, value, &type, &length, &data, &buffer, &offset);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_typedarray_info fail");
        return result;
    }
    if (type != napi_uint8_array) {
        IAM_LOGE("value is not napi_uint8_array");
        return napi_invalid_arg;
    }
    if (length > limitLen) {
        IAM_LOGE("array length reach limit");
        return napi_generic_failure;
    }
    array.resize(length);
    if (memcpy_s(array.data(), length, data, length) != EOK) {
        IAM_LOGE("memcpy_s fail");
        return napi_generic_failure;
    }
    return result;
}

napi_status UserAuthNapiHelper::GetUint64VectorFromUint8ArrayArrayValue(napi_env env, napi_value value,
    uint32_t limitLen, std::vector<uint64_t> &array)
{
    napi_status result = napi_ok;
    bool isArray = false;
    result = napi_is_array(env, value, &isArray);
    if (result != napi_ok || !isArray) {
        IAM_LOGE("napi_is_array fail");
        return napi_invalid_arg;
    }
    uint32_t outLength;
    result = napi_get_array_length(env, value, &outLength);
    IF_FALSE_LOGE_AND_RETURN_VAL((result == napi_ok), result);
    IAM_LOGI("outLength:%{public}d", outLength);
    IF_FALSE_LOGE_AND_RETURN_VAL((outLength <= limitLen), napi_invalid_arg);
    array.clear();
    array.reserve(outLength);
    for (uint32_t i = 0; i < outLength; i++) {
        napi_value element;
        result = napi_get_element(env, value, i, &element);
        IF_FALSE_LOGE_AND_RETURN_VAL((result == napi_ok), result);
        bool isTypedarray = false;
        result = napi_is_typedarray(env, element, &isTypedarray);
        if (result != napi_ok || !isTypedarray) {
            IAM_LOGE("napi_is_typedarray fail");
            return napi_invalid_arg;
        }
        napi_typedarray_type type;
        size_t length;
        void *data;
        napi_value buffer;
        size_t offset;
        result = napi_get_typedarray_info(env, element, &type, &length, &data, &buffer, &offset);
        IF_FALSE_LOGE_AND_RETURN_VAL((result == napi_ok), result);
        if (type != napi_uint8_array) {
            IAM_LOGE("type:%{public}d != napi_uint8_array", type);
            return napi_invalid_arg;
        }
        if (length != (sizeof(uint64_t) / sizeof(uint8_t))) {
            IAM_LOGE("length:%{public}zu", length);
            return napi_invalid_arg;
        }
        uint64_t dest = 0;
        if (memcpy_s(&dest, sizeof(uint64_t), data, sizeof(uint64_t)) != EOK) {
            IAM_LOGE("memcpy_s fail");
            return napi_invalid_arg;
        }
        array.push_back(dest);
    }
    return napi_ok;
}

napi_value UserAuthNapiHelper::Uint64ToNapiUint8Array(napi_env env, uint64_t value)
{
    void *data = nullptr;
    napi_value arraybuffer = nullptr;
    size_t length = sizeof(value);
    NAPI_CALL(env, napi_create_arraybuffer(env, length, &data, &arraybuffer));
    if (memcpy_s(data, length, reinterpret_cast<const void *>(&value), length) != EOK) {
        IAM_LOGE("memcpy_s fail");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, length, arraybuffer, 0, &result));
    return result;
}

napi_value UserAuthNapiHelper::Uint8VectorToNapiUint8Array(napi_env env,  std::vector<uint8_t> &value)
{
    void *data = nullptr;
    napi_value arraybuffer = nullptr;
    size_t length = value.size();
    NAPI_CALL(env, napi_create_arraybuffer(env, length, &data, &arraybuffer));
    if (memcpy_s(data, length, reinterpret_cast<const void *>(value.data()), length) != EOK) {
        IAM_LOGE("memcpy_s fail");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, length, arraybuffer, 0, &result));
    return result;
}

napi_status UserAuthNapiHelper::CallVoidNapiFunc(napi_env env, napi_ref funcRef, size_t argc, const napi_value *argv)
{
    napi_value funcVal;
    napi_status ret = napi_get_reference_value(env, funcRef, &funcVal);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_reference_value failed %{public}d", ret);
        return ret;
    }
    napi_value undefined;
    ret = napi_get_undefined(env, &undefined);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_undefined failed %{public}d", ret);
        return ret;
    }
    napi_value callResult;
    ret = napi_call_function(env, undefined, funcVal, argc, argv, &callResult);
    if (ret != napi_ok) {
        IAM_LOGE("napi_call_function failed %{public}d", ret);
    }
    return ret;
}

napi_status UserAuthNapiHelper::CallNapiFuncWithResult(napi_env env, napi_ref funcRef, size_t argc,
    const napi_value *argv, napi_value *result)
{
    napi_value funcVal;
    napi_status ret = napi_get_reference_value(env, funcRef, &funcVal);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_reference_value failed %{public}d", ret);
        return ret;
    }

    napi_value undefined;
    ret = napi_get_undefined(env, &undefined);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_undefined failed %{public}d", ret);
        return ret;
    }

    ret = napi_call_function(env, undefined, funcVal, argc, argv, result);
    if (ret != napi_ok) {
        IAM_LOGE("napi_call_function failed %{public}d", ret);
    }

    return ret;
}

napi_status UserAuthNapiHelper::SetBoolProperty(napi_env env, napi_value obj, const char *name, int32_t value)
{
    napi_value napiValue = nullptr;
    napi_status ret = napi_get_boolean(env, value, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_boolean failed %{public}d", ret);
        return ret;
    }

    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_status UserAuthNapiHelper::SetInt32Property(napi_env env, napi_value obj, const char *name, int32_t value)
{
    napi_value napiValue = nullptr;
    napi_status ret = napi_create_int32(env, value, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_status UserAuthNapiHelper::SetUint32Property(napi_env env, napi_value obj, const char *name, uint32_t value)
{
    napi_value napiValue = nullptr;
    napi_status ret = napi_create_uint32(env, value, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_uint32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_status UserAuthNapiHelper::SetUint8ArrayProperty(napi_env env,
    napi_value obj, const char *name, const std::vector<uint8_t> &value)
{
    size_t size = value.size();
    void *data;
    napi_value buffer;
    napi_status ret = napi_create_arraybuffer(env, size, &data, &buffer);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_arraybuffer failed %{public}d", ret);
        return ret;
    }
    if (size != 0) {
        if (memcpy_s(data, size, value.data(), value.size()) != EOK) {
            IAM_LOGE("memcpy_s failed");
            return napi_generic_failure;
        }
    }
    napi_value napiValue;
    ret = napi_create_typedarray(env, napi_uint8_array, size, buffer, 0, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_typedarray failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_status UserAuthNapiHelper::SetEnrolledStateProperty(napi_env env, napi_value obj,
    const char *name, EnrolledState &value)
{
    napi_value napiValue = nullptr;
    napi_status ret = napi_create_object(env, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    int32_t credentialDigest = static_cast<int32_t>(value.credentialDigest);
    int32_t credentialCount = static_cast<int32_t>(value.credentialCount);
    IAM_LOGI("get enrolled state success, credentialDigest = %{public}d, credentialCount = %{public}d",
        credentialDigest, credentialCount);
    ret = UserAuthNapiHelper::SetInt32Property(env, napiValue, "credentialDigest", credentialDigest);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env, napiValue, "credentialCount", credentialCount);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_value UserAuthNapiHelper::GetNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    napi_value value = nullptr;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty));
    if (!hasProperty) {
        return value;
    }
    NAPI_CALL(env, napi_get_named_property(env, object, propertyName.c_str(), &value));
    return value;
}

std::string UserAuthNapiHelper::GetStringFromValueUtf8(napi_env env, napi_value value)
{
    if (CheckNapiType(env, value, napi_string) != napi_ok) {
        return "";
    }
    std::string result;
    std::vector<char> str(MAX_STRING_LENGTH + 1, '\0');
    size_t length = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, value, &str[0], MAX_STRING_LENGTH, &length));
    if (length > 0) {
        return result.append(&str[0], length);
    }
    return result;
}

bool UserAuthNapiHelper::HasNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty), false);
    return hasProperty;
}

std::string UserAuthNapiHelper::GetStringPropertyUtf8(napi_env env, napi_value object, const std::string &propertyName)
{
    napi_value value = GetNamedProperty(env, object, propertyName);
    napi_status result = CheckNapiType(env, value, napi_string);
    if (result != napi_ok) {
        return "";
    }
    return GetStringFromValueUtf8(env, value);
}

bool UserAuthNapiHelper::SetStringPropertyUtf8(
    napi_env env, napi_value object, const std::string &name, const std::string &value)
{
    napi_value jsValue = nullptr;
    if (napi_create_string_utf8(env, value.c_str(), strlen(value.c_str()), &jsValue) != napi_ok) {
        IAM_LOGE("get string error");
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &valueType), napi_undefined);
    napi_set_named_property(env, object, name.c_str(), jsValue);
    return true;
}

bool UserAuthNapiHelper::GetInt32Array(napi_env env, napi_value obj, std::vector<uint32_t> vec)
{
    vec.clear();
    uint32_t len;
    napi_get_array_length(env, obj, &len);
    IAM_LOGI("GetInt32Array length: %{public}d", len);
    for (uint32_t index = 0; index < len; index++) {
        napi_value value;
        uint32_t getValue;
        NAPI_CALL_BASE(env, napi_get_element(env, obj, index, &value), napi_undefined);
        NAPI_CALL_BASE(env, napi_get_value_uint32(env, value, &getValue), napi_undefined);
        IAM_LOGI("vec[%{public}d]: %{public}d", index, len);
        vec.emplace_back(getValue);
    }
    return true;
}

bool UserAuthNapiHelper::CheckAuthType(int32_t authType)
{
    if (authType != AuthType::FACE && authType != AuthType::FINGERPRINT) {
        IAM_LOGE("authType check fail:%{public}d", authType);
        return false;
    }
    return true;
}

bool UserAuthNapiHelper::ConvertSizeToUint32(size_t in, uint32_t &out)
{
    if (in > UINT32_MAX) {
        IAM_LOGE("bad size");
        return false;
    }
    out = static_cast<uint32_t>(in);
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
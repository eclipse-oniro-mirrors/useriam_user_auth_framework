/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_instance_v9.h"

#include <string>

#include "iam_logger.h"
#include "iam_ptr.h"

#include "user_auth_api_event_reporter.h"
#include "user_auth_helper.h"
#include "user_auth_client_impl.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_AUTH_INSTANCE_V9

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const std::string AUTH_EVENT_RESULT = "result";
    const std::string AUTH_EVENT_TIP = "tip";
}

UserAuthResultCode AuthInstanceV9::GetAvailableStatusInner(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_TWO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        std::string msgStr = "Parameter error. The number of parameters should be 2.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    int32_t type;
    ret = napi_get_value_int32(env, argv[PARAM0], &type);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_value_int32 fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (!UserAuthHelper::CheckUserAuthType(type)) {
        IAM_LOGE("CheckUserAuthType fail");
        return UserAuthResultCode::TYPE_NOT_SUPPORT;
    }
    uint32_t level;
    ret = napi_get_value_uint32(env, argv[PARAM1], &level);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_value_int32 fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (!UserAuthHelper::CheckAuthTrustLevel(level)) {
        IAM_LOGE("CheckAuthTrustLevel fail");
        return UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT;
    }
    int32_t status = UserAuthClientImpl::Instance().GetNorthAvailableStatus(API_VERSION_9, AuthType(type),
        AuthTrustLevel(level));
    IAM_LOGI("result = %{public}d", status);
    if (status == PIN_EXPIRED) {
        return UserAuthResultCode::PIN_EXPIRED;
    }
    return UserAuthResultCode(UserAuthNapiHelper::GetResultCodeV9(status));
}

UserAuthResultCode AuthInstanceV9::GetAvailableStatus(napi_env env, napi_callback_info info)
{
    UserAuthApiEventReporter reporter("getAvailableStatus");
    UserAuthResultCode resultCode = GetAvailableStatusInner(env, info);
    if (resultCode != UserAuthResultCode::SUCCESS) {
        reporter.ReportFailed(resultCode);
    } else {
        reporter.ReportSuccess();
    }
    return resultCode;
}

AuthInstanceV9::AuthInstanceV9(napi_env env) : callback_(Common::MakeShared<UserAuthCallbackV9>(env))
{
    if (callback_ == nullptr) {
        IAM_LOGE("get null callback");
    }
}

napi_status AuthInstanceV9::InitChallenge(napi_env env, napi_value value)
{
    challenge_.clear();
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("challenge is null");
        return ret;
    }
    ret = UserAuthNapiHelper::GetUint8ArrayValue(env, value, MAX_CHALLENG_LEN, challenge_);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint8ArrayValue fail:%{public}d", ret);
    }
    IAM_LOGI("challenge size:%{public}zu", challenge_.size());
    return ret;
}

UserAuthResultCode AuthInstanceV9::Init(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_THREE];
    size_t argc = ARGS_THREE;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_THREE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    challenge_.clear();
    ret = InitChallenge(env, argv[PARAM0]);
    if (ret != napi_ok) {
        IAM_LOGE("InitChallenge fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    int32_t authType;
    ret = UserAuthNapiHelper::GetInt32Value(env, argv[PARAM1], authType);
    if (ret != napi_ok) {
        IAM_LOGE("GetInt32Value fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    if (!UserAuthNapiHelper::CheckAuthType(authType)) {
        IAM_LOGE("CheckAuthType fail");
        return UserAuthResultCode::TYPE_NOT_SUPPORT;
    }
    authType_ = AuthType(authType);
    uint32_t authTrustLevel;
    ret = UserAuthNapiHelper::GetUint32Value(env, argv[PARAM2], authTrustLevel);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint32Value fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    if (!UserAuthHelper::CheckAuthTrustLevel(authTrustLevel)) {
        IAM_LOGE("CheckAuthTrustLevel fail");
        return UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT;
    }
    authTrustLevel_ = AuthTrustLevel(authTrustLevel);
    return UserAuthResultCode::SUCCESS;
}

std::shared_ptr<JsRefHolder> AuthInstanceV9::GetCallback(napi_env env, napi_value value)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_object);
    if (ret != napi_ok) {
        IAM_LOGE("CheckNapiType fail:%{public}d", ret);
        return nullptr;
    }
    napi_value callbackValue;
    ret = napi_get_named_property(env, value, "callback", &callbackValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_named_property fail:%{public}d", ret);
        return nullptr;
    }
    return Common::MakeShared<JsRefHolder>(env, callbackValue);
}

UserAuthResultCode AuthInstanceV9::On(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_TWO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    static const size_t maxLen = 10;
    char str[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], str, len);
    if (ret != napi_ok) {
        IAM_LOGE("GetStrValue fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    auto callbackRef = GetCallback(env, argv[PARAM1]);
    if (callbackRef == nullptr || !callbackRef->IsValid()) {
        IAM_LOGE("GetCallback fail");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    if (str == AUTH_EVENT_RESULT) {
        IAM_LOGI("SetResultCallback");
        callback_->SetResultCallback(callbackRef);
        return UserAuthResultCode::SUCCESS;
    } else if (str == AUTH_EVENT_TIP) {
        IAM_LOGI("SetAcquireCallback");
        callback_->SetAcquireCallback(callbackRef);
        return UserAuthResultCode::SUCCESS;
    } else {
        IAM_LOGE("invalid event:%{public}s", str);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
}

UserAuthResultCode AuthInstanceV9::Off(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    static const size_t maxLen = 10;
    char str[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], str, len);
    if (ret != napi_ok) {
        IAM_LOGE("GetStrValue fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (str == AUTH_EVENT_RESULT) {
        callback_->ClearResultCallback();
        IAM_LOGI("clear result callback");
        return UserAuthResultCode::SUCCESS;
    } else if (str == AUTH_EVENT_TIP) {
        callback_->ClearAcquireCallback();
        IAM_LOGI("clear tip callback");
        return UserAuthResultCode::SUCCESS;
    } else {
        IAM_LOGE("invalid event:%{public}s", str);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
}

UserAuthResultCode AuthInstanceV9::Start(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_ZERO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (isAuthStarted_) {
        IAM_LOGE("auth already started");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    contextId_ = UserAuthClientImpl::Instance().BeginNorthAuthentication(API_VERSION_9,
        challenge_, authType_, authTrustLevel_, callback_);
    isAuthStarted_ = true;
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode AuthInstanceV9::Cancel(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_ZERO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (!isAuthStarted_) {
        IAM_LOGE("auth not started");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    int32_t result = UserAuthClient::GetInstance().CancelAuthentication(contextId_);
    if (result != ResultCode::SUCCESS) {
        IAM_LOGE("CancelAuthentication fail:%{public}d", result);
        return UserAuthResultCode(UserAuthNapiHelper::GetResultCodeV9(result));
    }
    return UserAuthResultCode::SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

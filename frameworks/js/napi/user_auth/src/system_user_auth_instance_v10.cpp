/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "system_user_auth_instance_v10.h"

#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_auth_helper.h"
#include "user_auth_napi_helper.h"
#include "user_auth_napi_client_impl.h"
#include "user_auth_param_utils.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_SYSTEM_USER_AUTH_INSTANCE_V10_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {

SystemUserAuthInstanceNapi::SystemUserAuthInstanceNapi(napi_env env)
    : callback_(Common::MakeShared<UserAuthCallbackV10>(env))
{
    if (callback_ == nullptr) {
        IAM_LOGE("get null callback");
    }
    authParam_.authTrustLevel = AuthTrustLevel::ATL1;
    authParam_.userId = INVALID_USER_ID;
    authParam_.isUserIdSpecified = false;
    authParam_.skipLockedBiometricAuth = false;
    authParam_.reuseUnlockResult.isReuse = false;
}

UserAuthResultCode SystemUserAuthInstanceNapi::Init(napi_env env, napi_callback_info info)
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
        std::string msgStr = "Parameter error. The number of parameters should be 1";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    UserAuthResultCode errCode = UserAuthParamUtils::InitAuthParam(env, argv[PARAM0], authParam_);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("AuthParamInner type error, errorCode: %{public}d", errCode);
        return errCode;
    }
    if (authParam_.authTypes.size() != 1) {
        IAM_LOGE("authType must contain exactly one authentication type, typeCount:%{public}zu",
            authParam_.authTypes.size());
        std::string msgStr = "Parameter error. \"authType\" must contain exactly one authentication type.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    if (authParam_.remoteAuthParam.has_value() && authParam_.tokenSchedule.has_value()) {
        IAM_LOGE("remoteAuthOptions cannot be specified together with scheduledAuthTokenOptions");
        std::string msgStr = "Parameter error. \"remoteAuthOptions\" and \"scheduledAuthTokenOptions\""
            " cannot be specified together.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    IAM_LOGI("Init SUCCESS");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode SystemUserAuthInstanceNapi::SetResultCallback(napi_env env, napi_value value)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    auto callbackRef = Common::MakeShared<JsRefHolder>(env, value);
    if (callbackRef == nullptr || !callbackRef->IsValid()) {
        IAM_LOGE("getSystemUserAuthInstance onResult GetCallback fail");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    if (callback_->HasResultCallback()) {
        IAM_LOGE("result callback has been registered");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    callback_->SetResultCallback(callbackRef);
    IAM_LOGI("SetResultCallback success");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode SystemUserAuthInstanceNapi::SetAcquireInfoCallback(napi_env env, napi_value value)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    auto callbackRef = Common::MakeShared<JsRefHolder>(env, value);
    if (callbackRef == nullptr || !callbackRef->IsValid()) {
        IAM_LOGE("getSystemUserAuthInstance onAcquireInfo GetCallback fail");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    if (callback_->HasAcquireCallback()) {
        IAM_LOGE("acquire callback has been registered");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    callback_->SetAcquireCallback(callbackRef);
    IAM_LOGI("SetAcquireCallback success");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode SystemUserAuthInstanceNapi::OnResult(napi_env env, napi_callback_info info)
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
        std::string msgStr = "Parameter error. The number of parameters should be 1";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    return SetResultCallback(env, argv[PARAM0]);
}

UserAuthResultCode SystemUserAuthInstanceNapi::OffResult(napi_env env, napi_callback_info info)
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
    if (argc != ARGS_ONE && argc != ARGS_ZERO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        std::string msgStr = "Parameter error. The number of parameters should be 0 or 1";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    std::lock_guard<std::mutex> guard(mutex_);
    callback_->ClearResultCallback();
    IAM_LOGI("offResult success");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode SystemUserAuthInstanceNapi::OnAcquireInfo(napi_env env, napi_callback_info info)
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
        std::string msgStr = "Parameter error. The number of parameters should be 1";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    return SetAcquireInfoCallback(env, argv[PARAM0]);
}

UserAuthResultCode SystemUserAuthInstanceNapi::OffAcquireInfo(napi_env env, napi_callback_info info)
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
    if (argc != ARGS_ONE && argc != ARGS_ZERO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        std::string msgStr = "Parameter error. The number of parameters should be 0 or 1";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    std::lock_guard<std::mutex> guard(mutex_);
    callback_->ClearAcquireCallback();
    IAM_LOGI("offAcquireInfo success");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode SystemUserAuthInstanceNapi::Start(napi_env env, napi_callback_info info)
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
        std::string msgStr = "Parameter error. The number of parameters should be 0";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (isStarted_ || isFinished_) {
        IAM_LOGE("instance already started or finished");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    contextId_ = UserAuthNapiClientImpl::Instance().BeginAuthentication(API_VERSION_10, authParam_, callback_);
    isStarted_ = true;
    isFinished_ = true;
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode SystemUserAuthInstanceNapi::Cancel(napi_env env, napi_callback_info info)
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
        std::string msgStr = "Parameter error. The number of parameters should be 0";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (!isStarted_) {
        IAM_LOGE("auth not started");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    int32_t result = UserAuthNapiClientImpl::Instance().CancelAuthentication(contextId_,
        ResultCode::CANCELED);
    if (result != ResultCode::SUCCESS) {
        IAM_LOGE("CancelAuthentication fail:%{public}d", result);
        return UserAuthResultCode(UserAuthHelper::GetResultCodeV10(result));
    }
    isStarted_ = false;
    return UserAuthResultCode::SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

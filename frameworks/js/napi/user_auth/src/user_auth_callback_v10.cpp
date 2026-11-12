/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "user_auth_callback_v10.h"

#include <uv.h>

#include "napi/native_node_api.h"

#include "iam_ptr.h"
#include "iam_logger.h"
#include "auth_common.h"
#include "user_auth_helper.h"
#include "user_auth_client_impl.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_CALLBACK_VERSION_10

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct ResultCallbackV10Holder {
    std::shared_ptr<UserAuthCallbackV10> callback {nullptr};
    ResultInfo resultInfo {};
    napi_env env {nullptr};
};

struct AuthTipInfoCallbackHolder {
    std::shared_ptr<UserAuthCallbackV10> callback {nullptr};
    int32_t tipCode {0};
    int32_t tipType {0};
    napi_env env {nullptr};
};

struct AcquireInfoCallbackHolder {
    std::shared_ptr<UserAuthCallbackV10> callback {nullptr};
    int32_t module {0};
    int32_t acquireInfo {0};
    std::vector<uint8_t> extraInfo {};
    napi_env env {nullptr};
};

constexpr size_t CREDENTIAL_ID_LEN = 8;
constexpr uint32_t BITS_PER_BYTE = 8;

// Only tips representable by UserAuthType and UserAuthTipCode are reported to acquire-info callbacks.
bool IsStandardAuthTip(int32_t module, int32_t acquireInfo)
{
    if (!UserAuthHelper::CheckUserAuthType(module)) {
        return false;
    }
    return acquireInfo >= UserAuthTipCode::TIP_CODE_FAIL &&
        acquireInfo <= UserAuthTipCode::TIP_CODE_COMPARE_FAIL_WITH_FROZEN;
}

void OnResultV10Work(std::shared_ptr<ResultCallbackV10Holder> resultHolder)
{
    IAM_LOGD("start");
    if (resultHolder == nullptr || resultHolder->callback == nullptr) {
        IAM_LOGE("resultHolder is invalid");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(resultHolder->env, &scope);
    if (scope == nullptr) {
        IAM_LOGE("scope is invalid");
        return;
    }
    napi_status ret = resultHolder->callback->DoResultCallback(resultHolder->resultInfo);
    IAM_LOGD("DoResultCallback ret = %{public}d", ret);
    napi_close_handle_scope(resultHolder->env, scope);
}
}

UserAuthCallbackV10::UserAuthCallbackV10(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAuthCallbackV10 get null env");
    }
}

UserAuthCallbackV10::~UserAuthCallbackV10()
{
}

void UserAuthCallbackV10::SetResultCallback(const std::shared_ptr<JsRefHolder> &resultCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = resultCallback;
}

void UserAuthCallbackV10::ClearResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = nullptr;
}

std::shared_ptr<JsRefHolder> UserAuthCallbackV10::GetResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return resultCallback_;
}

bool UserAuthCallbackV10::HasResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return resultCallback_ != nullptr;
}

void UserAuthCallbackV10::SetTipCallback(const std::shared_ptr<JsRefHolder> &tipCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    tipCallback_ = tipCallback;
}

void UserAuthCallbackV10::ClearTipCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    tipCallback_ = nullptr;
}

std::shared_ptr<JsRefHolder> UserAuthCallbackV10::GetTipCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return tipCallback_;
}

bool UserAuthCallbackV10::HasTipCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return tipCallback_ != nullptr;
}

void UserAuthCallbackV10::SetAcquireCallback(const std::shared_ptr<JsRefHolder> &acquireCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    acquireCallback_ = acquireCallback;
}

void UserAuthCallbackV10::ClearAcquireCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    acquireCallback_ = nullptr;
}

std::shared_ptr<JsRefHolder> UserAuthCallbackV10::GetAcquireCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return acquireCallback_;
}

bool UserAuthCallbackV10::HasAcquireCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return acquireCallback_ != nullptr;
}

napi_status UserAuthCallbackV10::DoResultCallback(const ResultInfo &resultInfo)
{
    auto resultCallback = GetResultCallback();
    if (resultCallback == nullptr) {
        IAM_LOGE("resultCallback is null");
        return napi_ok;
    }
    IAM_LOGD("start");
    napi_value eventInfo;
    napi_status ret = napi_create_object(env_, &eventInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetResultInfoProperty(env_, eventInfo, resultInfo);
    if (ret != napi_ok) {
        IAM_LOGE("SetResultInfoProperty failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, resultCallback->Get(), ARGS_ONE, &eventInfo);
}

napi_status UserAuthCallbackV10::DoTipInfoCallBack(int32_t tipType, uint32_t tipCode)
{
    IAM_LOGI("DoTipInfoCallBack start, authType:%{public}d, tipCode:%{public}u", tipType, tipCode);
    auto tipCallback = GetTipCallback();
    if (tipCallback == nullptr) {
        IAM_LOGE("tipCallback is null");
        return napi_ok;
    }
    napi_value authTipInfo;
    napi_status ret = napi_create_object(env_, &authTipInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, authTipInfo, "tipType", tipType);
    if (ret != napi_ok) {
        IAM_LOGE("SetInt32Property tipType failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, authTipInfo, "tipCode", tipCode);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 tipCode failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::CallVoidNapiFunc(env_, tipCallback->Get(), ARGS_ONE, &authTipInfo);
    if (ret != napi_ok) {
        IAM_LOGE("CallVoidNapiFunc failed %{public}d", ret);
        return ret;
    }
    return ret;
}

napi_status UserAuthCallbackV10::DoAcquireInfoCallBack(int32_t module, int32_t acquireInfo,
    const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGD("start, module:%{public}d, acquireInfo:%{public}d, extraInfo len:%{public}zu", module, acquireInfo,
        extraInfo.size());
    auto acquireCallback = GetAcquireCallback();
    if (acquireCallback == nullptr) {
        IAM_LOGE("acquireCallback is null");
        return napi_ok;
    }
    napi_value authTipInfo = nullptr;
    napi_status ret = napi_create_object(env_, &authTipInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, authTipInfo, "tipType", module);
    if (ret != napi_ok) {
        IAM_LOGE("SetInt32Property tipType failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, authTipInfo, "tipCode", acquireInfo);
    if (ret != napi_ok) {
        IAM_LOGE("SetInt32Property tipCode failed %{public}d", ret);
        return ret;
    }
    std::vector<uint8_t> extraInfoCopy = extraInfo;
    napi_value extraInfoValue = UserAuthNapiHelper::Uint8VectorToNapiUint8Array(env_, extraInfoCopy);
    if (extraInfoValue == nullptr) {
        IAM_LOGE("Uint8VectorToNapiUint8Array failed");
        return napi_generic_failure;
    }
    ret = napi_set_named_property(env_, authTipInfo, "extraInfo", extraInfoValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property extraInfo failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, acquireCallback->Get(), ARGS_ONE, &authTipInfo);
}

void UserAuthCallbackV10::OnAcquireInfo(int32_t module, uint32_t acquireInfo,
    const UserIam::UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("start, authType:%{public}d, tipCode:%{public}u", module, acquireInfo);
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    SendTipInfoEvent(module, static_cast<int32_t>(acquireInfo));
    if (!IsStandardAuthTip(module, static_cast<int32_t>(acquireInfo))) {
        IAM_LOGI("drop non-standard tip, module:%{public}d, tipCode:%{public}u", module, acquireInfo);
        return;
    }
    SendAcquireInfoEvent(module, static_cast<int32_t>(acquireInfo), extraInfo.Serialize());
}

void UserAuthCallbackV10::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGD("start, result:%{public}d", result);
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<ResultCallbackV10Holder> resultHolder = Common::MakeShared<ResultCallbackV10Holder>();
    if (resultHolder == nullptr) {
        IAM_LOGE("resultHolder is null");
        return;
    }
    resultHolder->callback = shared_from_this();
    resultHolder->resultInfo.result = UserAuthHelper::GetResultCodeV10(result);
    resultHolder->env = env_;
    FillResultInfo(extraInfo, resultHolder->resultInfo);
    IAM_LOGI("result token size: %{public}zu.", resultHolder->resultInfo.token.size());
    auto task = [resultHolder] () {
        OnResultV10Work(resultHolder);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::UserAuthCallbackV10::OnResult")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

void UserAuthCallbackV10::SendTipInfoEvent(int32_t tipType, int32_t tipCode)
{
    std::shared_ptr<AuthTipInfoCallbackHolder> holder = Common::MakeShared<AuthTipInfoCallbackHolder>();
    if (holder == nullptr) {
        IAM_LOGE("tipInfoHolder is null");
        return;
    }
    holder->callback = shared_from_this();
    holder->tipType = tipType;
    holder->tipCode = tipCode;
    holder->env = env_;
    auto task = [holder]() {
        IAM_LOGD("start");
        if (holder == nullptr || holder->callback == nullptr) {
            IAM_LOGE("tipInfoHolder is invalid");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(holder->env, &scope);
        if (scope == nullptr) {
            IAM_LOGE("scope is invalid");
            return;
        }
        napi_status ret = holder->callback->DoTipInfoCallBack(holder->tipType, holder->tipCode);
        if (ret != napi_ok) {
            IAM_LOGE("DoTipInfoCallBack ret = %{public}d", ret);
        }
        napi_close_handle_scope(holder->env, scope);
    };
    if (napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::UserAuthCallbackV10::OnAcquireInfo") != napi_status::napi_ok) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

void UserAuthCallbackV10::SendAcquireInfoEvent(int32_t module, int32_t acquireInfo,
    const std::vector<uint8_t> &extraInfo)
{
    if (!HasAcquireCallback()) {
        return;
    }
    std::shared_ptr<AcquireInfoCallbackHolder> acquireHolder = Common::MakeShared<AcquireInfoCallbackHolder>();
    if (acquireHolder == nullptr) {
        IAM_LOGE("acquireHolder is null");
        return;
    }
    acquireHolder->callback = shared_from_this();
    acquireHolder->module = module;
    acquireHolder->acquireInfo = acquireInfo;
    acquireHolder->extraInfo = extraInfo;
    acquireHolder->env = env_;
    auto acquireTask = [acquireHolder]() {
        IAM_LOGD("start");
        if (acquireHolder == nullptr || acquireHolder->callback == nullptr) {
            IAM_LOGE("acquireHolder is invalid");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(acquireHolder->env, &scope);
        if (scope == nullptr) {
            IAM_LOGE("scope is invalid");
            return;
        }
        napi_status ret = acquireHolder->callback->DoAcquireInfoCallBack(acquireHolder->module,
            acquireHolder->acquireInfo, acquireHolder->extraInfo);
        if (ret != napi_ok) {
            IAM_LOGE("DoAcquireInfoCallBack ret = %{public}d", ret);
        }
        napi_close_handle_scope(acquireHolder->env, scope);
    };
    if (napi_send_event(env_, acquireTask, napi_eprio_immediate,
        "UserAuthNapi::UserAuthCallbackV10::OnAcquireInfoAcquire") != napi_status::napi_ok) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

void UserAuthCallbackV10::FillResultInfo(const Attributes &extraInfo, ResultInfo &resultInfo)
{
    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, resultInfo.token)) {
        IAM_LOGE("ATTR_SIGNATURE is null");
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_AUTH_TYPE, resultInfo.authType)) {
        IAM_LOGE("ATTR_AUTH_TYPE is null");
    }
    if (!extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST,
        resultInfo.enrolledState.credentialDigest)) {
        IAM_LOGE("ATTR_CREDENTIAL_DIGEST is null");
    }
    if (!extraInfo.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT,
        resultInfo.enrolledState.credentialCount)) {
        IAM_LOGE("ATTR_CREDENTIAL_COUNT is null");
    }
    int32_t int32Value = 0;
    if (extraInfo.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, int32Value)) {
        resultInfo.remainingAuthAttempts = int32Value;
    }
    if (extraInfo.GetInt32Value(Attributes::ATTR_FREEZING_TIME, int32Value)) {
        resultInfo.lockoutDuration = int32Value;
    }
    if (extraInfo.GetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, int32Value)) {
        resultInfo.nextPhaseLockoutDuration = int32Value;
    }
    uint64_t credentialId = 0;
    if (extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_ID, credentialId)) {
        resultInfo.credentialId.resize(CREDENTIAL_ID_LEN);
        for (size_t i = 0; i < CREDENTIAL_ID_LEN; ++i) {
            resultInfo.credentialId[i] =
                static_cast<uint8_t>((credentialId >> (i * BITS_PER_BYTE)) & 0xFF);
        }
    }
    if (extraInfo.GetInt32Value(Attributes::ATTR_USER_ID, int32Value)) {
        resultInfo.userId = int32Value;
    }
    int64_t int64Value = 0;
    if (extraInfo.GetInt64Value(Attributes::ATTR_PIN_EXPIRED_INFO, int64Value)) {
        resultInfo.pinValidityPeriod = int64Value;
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

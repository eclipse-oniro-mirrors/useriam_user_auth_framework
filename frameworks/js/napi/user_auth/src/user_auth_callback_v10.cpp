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
    int32_t result {0};
    std::vector<uint8_t> token {};
    int32_t authType {0};
    EnrolledState enrolledState {};
    napi_env env {nullptr};
};

struct AuthTipInfoCallbackHolder {
    std::shared_ptr<UserAuthCallbackV10> callback {nullptr};
    int32_t tipCode {0};
    int32_t tipType {0};
    napi_env env {nullptr};
};

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
    napi_status ret = resultHolder->callback->DoResultCallback(resultHolder->result, resultHolder->token,
        resultHolder->authType, resultHolder->enrolledState);
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

napi_status UserAuthCallbackV10::DoResultCallback(int32_t result,
    const std::vector<uint8_t> &token, int32_t authType, EnrolledState enrolledState)
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
    ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "result", result);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }

    if (!token.empty()) {
        ret = UserAuthNapiHelper::SetUint8ArrayProperty(env_, eventInfo, "token", token);
        if (ret != napi_ok) {
            IAM_LOGE("SetUint8ArrayProperty failed %{public}d", ret);
            return ret;
        }
    }

    if (UserAuthHelper::CheckUserAuthType(authType)) {
        ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "authType", authType);
        if (ret != napi_ok) {
            IAM_LOGE("napi_create_int32 failed %{public}d", ret);
            return ret;
        }
    }
    if (UserAuthResultCode(result) == UserAuthResultCode::SUCCESS || !token.empty()) {
        ret = UserAuthNapiHelper::SetEnrolledStateProperty(env_, eventInfo, "enrolledState", enrolledState);
        if (ret != napi_ok) {
            IAM_LOGE("SetEnrolledStateProperty failed %{public}d", ret);
            return ret;
        }
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
    std::shared_ptr<AuthTipInfoCallbackHolder> authTipInfoCallbackHolder =
        Common::MakeShared<AuthTipInfoCallbackHolder>();
    if (authTipInfoCallbackHolder == nullptr) {
        IAM_LOGE("resultHolder is null");
        return;
    }
    authTipInfoCallbackHolder->callback = shared_from_this();
    authTipInfoCallbackHolder->tipType = module;
    authTipInfoCallbackHolder->tipCode = static_cast<int32_t>(acquireInfo);
    authTipInfoCallbackHolder->env = env_;
    auto task = [authTipInfoCallbackHolder] () {
        IAM_LOGD("start");
        if (authTipInfoCallbackHolder == nullptr || authTipInfoCallbackHolder->callback == nullptr) {
            IAM_LOGE("authTipInfoCallbackHolder is invalid");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(authTipInfoCallbackHolder->env, &scope);
        if (scope == nullptr) {
            IAM_LOGE("scope is invalid");
            return;
        }
        napi_status ret = authTipInfoCallbackHolder->callback->DoTipInfoCallBack(authTipInfoCallbackHolder->tipType,
                                                                                 authTipInfoCallbackHolder->tipCode);
        if (ret != napi_ok) {
            IAM_LOGE("DoTipInfoCallBack ret = %{public}d", ret);
            napi_close_handle_scope(authTipInfoCallbackHolder->env, scope);
            return;
        }
        napi_close_handle_scope(authTipInfoCallbackHolder->env, scope);
    };
    if (napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::UserAuthCallbackV10::OnAcquireInfo") != napi_status::napi_ok) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
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
    resultHolder->result =  UserAuthHelper::GetResultCodeV10(result); // ResultCode -> UserAuthResultCode
    resultHolder->env = env_;
    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, resultHolder->token)) {
        IAM_LOGE("ATTR_SIGNATURE is null");
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_AUTH_TYPE, resultHolder->authType)) {
        IAM_LOGE("ATTR_AUTH_TYPE is null");
    }
    if (!extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, resultHolder->enrolledState.credentialDigest)) {
        IAM_LOGE("ATTR_CREDENTIAL_DIGEST is null");
    }
    if (!extraInfo.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, resultHolder->enrolledState.credentialCount)) {
        IAM_LOGE("ATTR_CREDENTIAL_COUNT is null");
    }
    IAM_LOGI("result token size: %{public}zu.", resultHolder->token.size());
    auto task = [resultHolder] () {
        OnResultV10Work(resultHolder);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::UserAuthCallbackV10::OnResult")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "user_auth_callback_v9.h"

#include <optional>
#include <uv.h>

#include "napi/native_node_api.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_CALLBACK_VERSION_9

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct ResultCallbackV9Holder {
    std::shared_ptr<UserAuthCallbackV9> callback {nullptr};
    int32_t result {0};
    std::vector<uint8_t> token {};
    std::optional<int32_t> remainTimes {std::nullopt};
    std::optional<int32_t> freezingTime {std::nullopt};
    napi_env env;
};

struct AcquireCallbackV9Holder {
    std::shared_ptr<UserAuthCallbackV9> callback {nullptr};
    int32_t module {0};
    uint32_t acquireInfo {0};
    napi_env env;
};
}

UserAuthCallbackV9::UserAuthCallbackV9(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAuthCallbackV9 get null env");
    }
}

UserAuthCallbackV9::~UserAuthCallbackV9()
{
}

void UserAuthCallbackV9::SetResultCallback(const std::shared_ptr<JsRefHolder> &resultCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = resultCallback;
}

void UserAuthCallbackV9::ClearResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = nullptr;
}

void UserAuthCallbackV9::SetAcquireCallback(const std::shared_ptr<JsRefHolder> &acquireCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    acquireCallback_ = acquireCallback;
}

void UserAuthCallbackV9::ClearAcquireCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    acquireCallback_ = nullptr;
}

std::shared_ptr<JsRefHolder> UserAuthCallbackV9::GetResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return resultCallback_;
}

std::shared_ptr<JsRefHolder> UserAuthCallbackV9::GetAcquireCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return acquireCallback_;
}

napi_status UserAuthCallbackV9::DoResultCallback(int32_t result, const std::vector<uint8_t> &token,
    std::optional<int32_t> &remainTimes, std::optional<int32_t> &freezingTime)
{
    auto resultCallback = GetResultCallback();
    if (resultCallback == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
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
    ret = UserAuthNapiHelper::SetUint8ArrayProperty(env_, eventInfo, "token", token);
    if (ret != napi_ok) {
        IAM_LOGE("SetUint8ArrayProperty failed %{public}d", ret);
        return ret;
    }

    if (remainTimes.has_value()) {
        ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "remainAttempts", remainTimes.value());
        if (ret != napi_ok) {
            IAM_LOGE("SetInt32Property failed %{public}d", ret);
            return ret;
        }
    }

    if (freezingTime.has_value()) {
        ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "lockoutDuration", freezingTime.value());
        if (ret != napi_ok) {
            IAM_LOGE("SetInt32Property failed %{public}d", ret);
            return ret;
        }
    }

    return UserAuthNapiHelper::CallVoidNapiFunc(env_, resultCallback->Get(), ARGS_ONE, &eventInfo);
}

napi_status UserAuthCallbackV9::DoAcquireCallback(int32_t module, uint32_t acquireInfo)
{
    auto acquireCallback = GetAcquireCallback();
    if (acquireCallback == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value eventInfo;
    napi_status ret = napi_create_object(env_, &eventInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "module", module);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetUint32Property(env_, eventInfo, "tip", acquireInfo);
    if (ret != napi_ok) {
        IAM_LOGE("SetUint32Property failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, acquireCallback->Get(), ARGS_ONE, &eventInfo);
}

void UserAuthCallbackV9::OnAcquireInfo(int32_t module, uint32_t acquireInfo,
    const UserIam::UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("start module:%{public}d acquireInfo:%{public}u", module, acquireInfo);
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<AcquireCallbackV9Holder> acquireHolder = Common::MakeShared<AcquireCallbackV9Holder>();
    if (acquireHolder == nullptr) {
        IAM_LOGE("acquireHolder is null");
        return;
    }
    acquireHolder->callback = shared_from_this();
    acquireHolder->module = module;
    acquireHolder->acquireInfo = acquireInfo;
    acquireHolder->env = env_;
    auto task = [acquireHolder] () {
        IAM_LOGI("start");
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
        napi_status ret = acquireHolder->callback->DoAcquireCallback(acquireHolder->module, acquireHolder->acquireInfo);
        if (ret != napi_ok) {
            IAM_LOGE("DoAcquireCallback fail %{public}d", ret);
            napi_close_handle_scope(acquireHolder->env, scope);
            return;
        }
        napi_close_handle_scope(acquireHolder->env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::UserAuthCallbackV9::OnAcquireInfo")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

void OnResultV9Work(std::shared_ptr<ResultCallbackV9Holder> resultHolder)
{
    IAM_LOGI("start");
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
        resultHolder->remainTimes, resultHolder->freezingTime);
    if (ret != napi_ok) {
        IAM_LOGE("DoResultCallback fail %{public}d", ret);
        napi_close_handle_scope(resultHolder->env, scope);
        return;
    }
    napi_close_handle_scope(resultHolder->env, scope);
}

void UserAuthCallbackV9::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", result);
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<ResultCallbackV9Holder> resultHolder = Common::MakeShared<ResultCallbackV9Holder>();
    if (resultHolder == nullptr) {
        IAM_LOGE("resultHolder is null");
        return;
    }
    resultHolder->callback = shared_from_this();
    resultHolder->result = UserAuthNapiHelper::GetResultCodeV9(result);
    resultHolder->env = env_;
    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, resultHolder->token)) {
        IAM_LOGE("ATTR_SIGNATURE is null");
    }

    int32_t remainTimes = 0;
    if (extraInfo.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTimes)) {
        resultHolder->remainTimes = remainTimes;
    } else {
        IAM_LOGE("ATTR_REMAIN_TIMES is null");
    }

    int32_t freezingTime = INT32_MAX;
    if (extraInfo.GetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime)) {
        resultHolder->freezingTime = freezingTime;
    } else {
        IAM_LOGE("ATTR_FREEZING_TIME is null");
    }
    auto task = [resultHolder] () {
        OnResultV9Work(resultHolder);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::UserAuthCallbackV9::OnResult")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

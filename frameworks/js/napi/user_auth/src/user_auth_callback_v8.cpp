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

#include "user_auth_callback_v8.h"

#include <optional>
#include <uv.h>

#include "napi/native_node_api.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_CALLBACK_VERSION_8

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct ResultCallbackV8Holder {
    std::shared_ptr<UserAuthCallbackV8> callback {nullptr};
    int32_t result {0};
    std::vector<uint8_t> token {};
    std::optional<int32_t> remainTimes {std::nullopt};
    std::optional<int32_t> freezingTime {std::nullopt};
    napi_env env;
};

struct AcquireCallbackV8Holder {
    std::shared_ptr<UserAuthCallbackV8> callback {nullptr};
    int32_t module {0};
    uint32_t acquireInfo {0};
    napi_env env;
};
}

UserAuthCallbackV8::UserAuthCallbackV8(napi_env env,
    const std::shared_ptr<JsRefHolder> &resultCallback, const std::shared_ptr<JsRefHolder> &acquireCallback)
    : env_(env), resultCallback_(resultCallback), acquireCallback_(acquireCallback)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAuthCallbackV8 get null env");
    }
}

UserAuthCallbackV8::~UserAuthCallbackV8()
{
}

napi_status UserAuthCallbackV8::DoResultCallback(int32_t result, const std::vector<uint8_t> &token,
    std::optional<int32_t> &remainTimes, std::optional<int32_t> &freezingTime)
{
    if (resultCallback_ == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value params[ARGS_TWO] = {nullptr};
    napi_status ret = napi_create_int32(env_, result, &params[PARAM0]);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_create_object(env_, &params[PARAM1]);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }

    if (remainTimes.has_value()) {
        ret = UserAuthNapiHelper::SetInt32Property(env_, params[PARAM1], "remainTimes", remainTimes.value());
        if (ret != napi_ok) {
            IAM_LOGE("SetInt32Property failed %{public}d", ret);
            return ret;
        }
    }

    if (freezingTime.has_value()) {
        ret = UserAuthNapiHelper::SetInt32Property(env_, params[PARAM1], "freezingTime", freezingTime.value());
        if (ret != napi_ok) {
            IAM_LOGE("SetInt32Property failed %{public}d", ret);
            return ret;
        }
    }

    ret = UserAuthNapiHelper::SetUint8ArrayProperty(env_, params[PARAM1], "token", token);
    if (ret != napi_ok) {
        IAM_LOGE("SetUint8ArrayProperty failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, resultCallback_->Get(), ARGS_TWO, params);
}

napi_status UserAuthCallbackV8::DoAcquireCallback(int32_t module, uint32_t acquireInfo)
{
    if (acquireCallback_ == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value params[ARGS_TWO];
    napi_status ret = napi_create_int32(env_, module, &params[PARAM0]);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_create_uint32(env_, acquireInfo, &params[PARAM1]);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_uint32 failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, acquireCallback_->Get(), ARGS_TWO, params);
}

void UserAuthCallbackV8::OnAcquireInfo(int32_t module, uint32_t acquireInfo,
    const UserIam::UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("start module:%{public}d acquireInfo:%{public}u", module, acquireInfo);
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<AcquireCallbackV8Holder> acquireHolder = Common::MakeShared<AcquireCallbackV8Holder>();
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
        "UserAuthNapi::UserAuthCallbackV8::OnAcquireInfo")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

void OnResultV8Work(std::shared_ptr<ResultCallbackV8Holder> resultHolder)
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

void UserAuthCallbackV8::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", UserAuthNapiHelper::GetResultCodeV8(result));
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<ResultCallbackV8Holder> resultHolder = Common::MakeShared<ResultCallbackV8Holder>();
    if (resultHolder == nullptr) {
        IAM_LOGE("resultHolder is null");
        return;
    }
    resultHolder->callback = shared_from_this();
    resultHolder->result = UserAuthNapiHelper::GetResultCodeV8(result);
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
        OnResultV8Work(resultHolder);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::UserAuthCallbackV::OnResult")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

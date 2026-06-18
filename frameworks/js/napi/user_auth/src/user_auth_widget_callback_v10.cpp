/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "user_auth_widget_callback_v10.h"

#include <uv.h>

#include "napi/native_node_api.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_FILE_ID LOG_FILE_USER_AUTH_WIDGET_CALLBACK_V10_NAPI
#define LOG_TAG "USER_AUTH_NAPI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct CallbackHolder {
    std::shared_ptr<UserAuthWidgetCallback> callback {nullptr};
    std::string cmdData;
    napi_env env;
};
}

UserAuthWidgetCallback::UserAuthWidgetCallback(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAuthWidgetCallback get null env");
    }
}

UserAuthWidgetCallback::~UserAuthWidgetCallback()
{
}

void UserAuthWidgetCallback::SetCommandCallback(const std::shared_ptr<JsRefHolder> &callback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    commandCallback_ = callback;
}

void UserAuthWidgetCallback::ClearCommandCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    commandCallback_ = nullptr;
}

bool UserAuthWidgetCallback::HasCommandCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return commandCallback_ != nullptr;
}

std::shared_ptr<JsRefHolder> UserAuthWidgetCallback::GetCommandCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return commandCallback_;
}

napi_status UserAuthWidgetCallback::DoCommandCallback(const std::string &cmdData)
{
    auto commandCallback = GetCommandCallback();
    if (commandCallback == nullptr) {
        return napi_ok;
    }
    IAM_LOGD("start");
    napi_value eventInfo = nullptr;
    napi_status ret = napi_create_string_utf8(env_, cmdData.c_str(), cmdData.size(), &eventInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, commandCallback->Get(), ARGS_ONE, &eventInfo);
}

void UserAuthWidgetCallback::SendCommand(const std::string &cmdData)
{
    IAM_LOGD("start");
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<CallbackHolder> holder = Common::MakeShared<CallbackHolder>();
    if (holder == nullptr) {
        IAM_LOGE("holder is null");
        return;
    }
    holder->callback = shared_from_this();
    holder->cmdData = cmdData;
    holder->env = env_;
    auto task = [holder] () {
        IAM_LOGI("start");
        if (holder == nullptr || holder->callback == nullptr) {
            IAM_LOGE("holder is invalid");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(holder->env, &scope);
        if (scope == nullptr) {
            IAM_LOGE("scope is invalid");
            return;
        }
        napi_status ret = holder->callback->DoCommandCallback(holder->cmdData);
        if (ret != napi_ok) {
            IAM_LOGE("DoResultCallback fail %{public}d", ret);
            napi_close_handle_scope(holder->env, scope);
            return;
        }
        napi_close_handle_scope(holder->env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::UserAuthWidgetCallback::SendCommand")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

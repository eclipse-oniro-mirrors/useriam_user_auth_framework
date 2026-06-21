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

#include "remote_auth_callback_service.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_common_defines.h"
#include "user_auth_types.h"
#include "user_auth_client_callback.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
RemoteAuthCallbackService::RemoteAuthCallbackService(const std::shared_ptr<RemoteAuthClientCallback> &impl)
    : callback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, remote auth callback return default result to caller");
            impl->OnRemoteAuthResult({}, GENERAL_ERROR, {});
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

RemoteAuthCallbackService::~RemoteAuthCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t RemoteAuthCallbackService::OnGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
    const sptr<ISetWidgetParamCallback>& setWidgetParamCallback)
{
    IAM_LOGI("start");
    if (callback_ == nullptr) {
        return GENERAL_ERROR;
    }

    auto callbackWrapper = Common::MakeShared<SetWidgetParamClientCallback>(setWidgetParamCallback);
    callback_->OnGetRemoteAuthWidgetParam(challenge, callbackWrapper);
    return SUCCESS;
}

int32_t RemoteAuthCallbackService::OnRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t resultCode,
    const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    if (callback_ == nullptr) {
        return GENERAL_ERROR;
    }
    Attributes attribute(extraInfo);
    callback_->OnRemoteAuthResult(challenge, resultCode, attribute);
    return SUCCESS;
}

int32_t RemoteAuthCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t RemoteAuthCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "user_access_ctrl_callback_service.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_common_defines.h"

#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_CALLBACK_SERVICE
#define LOG_TAG "USER_ACCESS_CTRL_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
VerifyTokenCallbackService::VerifyTokenCallbackService(
    const std::shared_ptr<VerifyTokenCallback> &impl) : verifyTokenCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user access ctrl service death, return default verify token result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

VerifyTokenCallbackService::~VerifyTokenCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t VerifyTokenCallbackService::OnVerifyTokenResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start, verify token result: %{public}d", resultCode);
    if (verifyTokenCallback_ == nullptr) {
        IAM_LOGE("verifyTokenCallback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes attributes(extraInfo);
    verifyTokenCallback_->OnResult(resultCode, attributes);
    return SUCCESS;
}

int32_t VerifyTokenCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t VerifyTokenCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
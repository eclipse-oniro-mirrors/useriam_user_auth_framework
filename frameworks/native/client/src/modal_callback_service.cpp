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

#include "modal_callback_service.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ModalCallbackService::ModalCallbackService(const std::shared_ptr<UserAuthModalClientCallback> &impl)
    : modalCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuthWidget"))
{
    IAM_LOGI("set modal callback");
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, auth widget callback return default result to caller");
            uint64_t contextId = 0;
            std::string cmdData = "";
            impl->SendCommand(contextId, cmdData);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

ModalCallbackService::~ModalCallbackService()
{
    IAM_LOGI("~ModalCallbackService clean");
    iamHitraceHelper_= nullptr;
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

void ModalCallbackService::SendCommand(uint64_t contextId, const std::string &cmdData)
{
    IAM_LOGI("SendCommand start");
    if (modalCallback_ == nullptr) {
        IAM_LOGE("modal callback is nullptr");
        return;
    }
    modalCallback_->SendCommand(contextId, cmdData);
    iamHitraceHelper_ = nullptr;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
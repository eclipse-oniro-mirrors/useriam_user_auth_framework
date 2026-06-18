/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "auth_common.h"
#include "user_auth_callback_service.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_FILE_ID LOG_FILE_USER_AUTH_CALLBACK_SERVICE
#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UserAuthCallbackService::UserAuthCallbackService(const std::shared_ptr<AuthenticationCallback> &impl)
    : authCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuth InnerKit"))
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, auth callback return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

UserAuthCallbackService::UserAuthCallbackService(const std::shared_ptr<AuthenticationCallback> &impl,
    const std::shared_ptr<UserAuthModalClientCallback> &modalCallback)
    : authCallback_(impl), modalCallback_(modalCallback),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuth InnerKit"))
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, auth callback return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

UserAuthCallbackService::UserAuthCallbackService(const std::shared_ptr<IdentificationCallback> &impl)
    : identifyCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuth InnerKit"))
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, identify callback return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

UserAuthCallbackService::UserAuthCallbackService(const std::shared_ptr<PrepareRemoteAuthCallback> &impl)
    : prepareRemoteAuthCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuth InnerKit"))
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, prepare remote auth callback return default result to caller");
            impl->OnResult(GENERAL_ERROR);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

UserAuthCallbackService::~UserAuthCallbackService()
{
    IAM_LOGD("start");
    iamHitraceHelper_= nullptr;
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t UserAuthCallbackService::OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGD("start, result:%{public}d", resultCode);
    Attributes attribute(extraInfo);
    if (authCallback_ != nullptr) {
        if (modalCallback_ != nullptr) {
            IAM_LOGI("IsModalInit :%{public}d, IsModalDestroy :%{public}d", modalCallback_->IsModalInit(),
                modalCallback_->IsModalDestroy());
            if (modalCallback_->IsModalInit() && !modalCallback_->IsModalDestroy()) {
                const uint32_t sleepTime = 100000;
                usleep(sleepTime);
                IAM_LOGI("process result continue");
            }
        }
        authCallback_->OnResult(resultCode, attribute);
    } else if (identifyCallback_ != nullptr) {
        identifyCallback_->OnResult(resultCode, attribute);
    } else if (prepareRemoteAuthCallback_ != nullptr) {
        prepareRemoteAuthCallback_->OnResult(resultCode);
    } else {
        IAM_LOGE("all callback is nullptr");
        return GENERAL_ERROR;
    }
    iamHitraceHelper_= nullptr;
    return SUCCESS;
}

int32_t UserAuthCallbackService::OnAcquireInfo(int32_t module, int32_t acquireInfo,
    const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGD("start, module:%{public}d acquireInfo:%{public}d", module, acquireInfo);
    Attributes attribute(extraInfo);
    if (authCallback_ != nullptr) {
        // only modal extension need to wait modal uec release less than 300ms.
        if (modalCallback_ != nullptr) {
            IAM_LOGI("IsModalInit :%{public}d, IsModalDestroy :%{public}d", modalCallback_->IsModalInit(),
                modalCallback_->IsModalDestroy());
            if (modalCallback_->IsModalInit() && !modalCallback_->IsModalDestroy() &&
                acquireInfo == UserAuthTipCode::TIP_CODE_WIDGET_RELEASED) {
                const uint32_t sleepTime = 300000;
                usleep(sleepTime);
                IAM_LOGI("process acquireInfo continue");
            }
        }
        authCallback_->OnAcquireInfo(module, acquireInfo, attribute);
    } else if (identifyCallback_ != nullptr) {
        identifyCallback_->OnAcquireInfo(module, acquireInfo, attribute);
    } else if (prepareRemoteAuthCallback_ != nullptr) {
        IAM_LOGE("prepare remote auth callback not support acquire info");
    } else {
        IAM_LOGE("all callback is nullptr");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t UserAuthCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}

GetExecutorPropertyCallbackService::GetExecutorPropertyCallbackService(const std::shared_ptr<GetPropCallback> &impl)
    : getPropCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, get prop callback return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

GetExecutorPropertyCallbackService::~GetExecutorPropertyCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t GetExecutorPropertyCallbackService::OnGetExecutorPropertyResult(int32_t resultCode,
    const std::vector<uint8_t> &attributes)
{
    IAM_LOGD("start, result:%{public}d", resultCode);
    if (getPropCallback_ == nullptr) {
        IAM_LOGE("get prop callback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes attribute(attributes);
    getPropCallback_->OnResult(resultCode, attribute);
    return SUCCESS;
}

int32_t GetExecutorPropertyCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t GetExecutorPropertyCallbackService::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}

SetExecutorPropertyCallbackService::SetExecutorPropertyCallbackService(const std::shared_ptr<SetPropCallback> &impl)
    : setPropCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, set prop callback return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

SetExecutorPropertyCallbackService::~SetExecutorPropertyCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t SetExecutorPropertyCallbackService::OnSetExecutorPropertyResult(int32_t resultCode)
{
    IAM_LOGD("start, result:%{public}d", resultCode);
    if (setPropCallback_ == nullptr) {
        IAM_LOGE("set prop callback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes attr;
    setPropCallback_->OnResult(resultCode, attr);
    return SUCCESS;
}

int32_t SetExecutorPropertyCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t SetExecutorPropertyCallbackService::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
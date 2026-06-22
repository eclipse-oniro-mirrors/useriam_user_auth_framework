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

#include "modal_extension_callback.h"

#include "ability.h"
#include "ui_holder_extension_context.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "user_auth_napi_client_impl.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_MODAL_EXTENSION_CALLBACK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ModalExtensionCallback::ModalExtensionCallback()
{}

ModalExtensionCallback::~ModalExtensionCallback()
{}

void ModalExtensionCallback::OnResult(int32_t code, const AAFwk::Want& result)
{
    IAM_LOGI("OnResult, code: %{public}d", code);
}

void ModalExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    IAM_LOGI("OnReceive");
}

void ModalExtensionCallback::OnRelease(int32_t code)
{
    IAM_LOGI("OnRelease, code: %{public}d", code);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (code != 0) {
        CancelAuthentication();
    }
    ReleaseOrErrorHandle(code);
}

void ModalExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    IAM_LOGE("OnError, name:  %{public}s, message:  %{public}s", name.c_str(), message.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    CancelAuthentication();
    ReleaseOrErrorHandle(code);
}

void ModalExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    IAM_LOGI("OnRemoteReady");
}

void ModalExtensionCallback::OnDestroy()
{
    IAM_LOGI("OnDestroy");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isDestroy_ = true;
}

void ModalExtensionCallback::SetSessionId(int32_t sessionId)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    sessionId_ = sessionId;
}

void ModalExtensionCallback::SetContextId(uint64_t contextId)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    contextId_ = contextId;
}

void ModalExtensionCallback::SetAbilityContext(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    abilityContext_ = abilityContext;
}

void ModalExtensionCallback::SetHolderContext(
    std::shared_ptr<OHOS::AbilityRuntime::UIHolderExtensionContext> uiHolderContext)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    uiHolderContext_ = uiHolderContext;
}

void ModalExtensionCallback::ReleaseOrErrorHandle(int32_t code)
{
    IAM_LOGI("ReleaseOrErrorHandle start, code: %{public}d", code);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (abilityContext_ != nullptr) {
        Ace::UIContent* uiContent = abilityContext_->GetUIContent();
        if (uiContent == nullptr) {
            IAM_LOGE("uiContent is null");
            return;
        }
        uiContent->CloseModalUIExtension(sessionId_);
    }
    if (uiHolderContext_ != nullptr) {
        Ace::UIContent* uiContent = uiHolderContext_->GetUIContent();
        if (uiContent == nullptr) {
            IAM_LOGE("uiContent is null");
            return;
        }
        uiContent->CloseModalUIExtension(sessionId_);
    }
    IAM_LOGI("ReleaseOrErrorHandle end");
    isDestroy_ = true;
    return;
}

bool ModalExtensionCallback::IsModalDestroy()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return isDestroy_;
}

void ModalExtensionCallback::CancelAuthentication()
{
    // cancel for failed
    int32_t code = UserAuthNapiClientImpl::Instance().CancelAuthentication(contextId_, CancelReason::MODAL_RUN_ERROR);
    IAM_LOGI("CancelAuthentication, code: %{public}d", code);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
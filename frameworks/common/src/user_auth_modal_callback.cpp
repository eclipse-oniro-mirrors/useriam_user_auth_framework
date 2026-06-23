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

#include "user_auth_modal_callback.h"

#include "ability.h"
#include "ui_holder_extension_context.h"
#include "want.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "user_auth_napi_client_impl.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_MODAL_CALLBACK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UserAuthModalCallback::UserAuthModalCallback(const std::shared_ptr<AbilityRuntime::Context> context) : context_(context)
{}
UserAuthModalCallback::UserAuthModalCallback(const sptr<OHOS::Rosen::Window> window) : window_(window)
{}

UserAuthModalCallback::~UserAuthModalCallback()
{}

void UserAuthModalCallback::SendCommand(uint64_t contextId, const std::string &cmdData)
{
    IAM_LOGI("SendCommand start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (contextId == contextId_ && cmdData.empty()) {
        IAM_LOGI("stop modal");
        ReleaseModal();
        return;
    }
    IAM_LOGI("widgetParam context not null, process as modal application");
    if (contextId == 0 || cmdData.empty()) {
        IAM_LOGI("stop modal for invalid request");
        isInitError_ = true;
        CancelAuthentication(contextId, CancelReason::MODAL_CREATE_ERROR);
        return;
    }
    contextId_ = contextId;
    bool createModalRet = CreateUIExtension(contextId, cmdData);
    // Cancel for failed
    if (!createModalRet) {
        IAM_LOGE("create modal error, createModalRet: %{public}d", createModalRet);
        isInitError_ = true;
        CancelAuthentication(contextId, CancelReason::MODAL_CREATE_ERROR);
        return;
    }
    IAM_LOGI("create modal success");
    isInit_ = true;
}

bool UserAuthModalCallback::IsModalInit()
{
    IAM_LOGD("get is modal init");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return isInit_;
}

bool UserAuthModalCallback::IsModalDestroy()
{
    IAM_LOGD("get is modal on destroy");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isInitError_ || (uiExtCallback_ != nullptr && uiExtCallback_->IsModalDestroy())) {
        IAM_LOGI("modal on destroy");
        return true;
    }
    return false;
}

Ace::UIContent *UserAuthModalCallback::InitAndGetUIContent()
{
    Ace::UIContent *uiContent = nullptr;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext = nullptr;
    std::shared_ptr<AbilityRuntime::UIHolderExtensionContext> holderContext = nullptr;
    if (context_ != nullptr) {
        IAM_LOGI("use context");
        abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context_);
        if (abilityContext == nullptr) {
            IAM_LOGI("abilityContext is nullptr");
            holderContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIHolderExtensionContext>(context_);
            if (holderContext == nullptr) {
                IAM_LOGE("uiExtensionContext is nullptr");
                return nullptr;
            }
            uiContent = holderContext->GetUIContent();
        } else {
            uiContent = abilityContext->GetUIContent();
        }
    } else if (window_ != nullptr) {
        IAM_LOGI("use window");
        uiContent = window_->GetUIContent();
    }
    if (uiContent == nullptr) {
        IAM_LOGE("uiContent is nullptr");
        return nullptr;
    }

    uiExtCallback_ = std::make_shared<ModalExtensionCallback>();
    if (uiExtCallback_ == nullptr) {
        IAM_LOGI("uiExtCallback_ is nullptr");
        return nullptr;
    }
    uiExtCallback_->SetAbilityContext(abilityContext);
    uiExtCallback_->SetHolderContext(holderContext);
    uiExtCallback_->SetWindow(window_);
    return uiContent;
}

bool UserAuthModalCallback::CreateUIExtension(uint64_t contextId, const std::string &cmdData)
{
    Ace::UIContent *uiContent = InitAndGetUIContent();
    if (uiContent == nullptr) {
        IAM_LOGE("uiContent invalid");
        return false;
    }

    AAFwk::Want want;
    std::string targetBundleName = "com.ohos.useriam.authwidget";
    std::string targetAbilityName = "UserAuthModalUIAbility";
    want.SetElementName(targetBundleName, targetAbilityName);

    std::string typeKey = "ability.want.params.uiExtensionType";
    std::string typeValue = "sys/commonUI";
    want.SetParam(typeKey, typeValue);
    std::string commandKey = "parameters";
    want.SetParam(commandKey, cmdData);

    uiExtCallback_->SetContextId(contextId);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        .onRelease = std::bind(&ModalExtensionCallback::OnRelease, uiExtCallback_, std::placeholders::_1),
        .onResult = std::bind(&ModalExtensionCallback::OnResult, uiExtCallback_,
            std::placeholders::_1, std::placeholders::_2),
        .onReceive = std::bind(&ModalExtensionCallback::OnReceive, uiExtCallback_, std::placeholders::_1),
        .onError = std::bind(&ModalExtensionCallback::OnError, uiExtCallback_,
            std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
        .onRemoteReady = std::bind(&ModalExtensionCallback::OnRemoteReady, uiExtCallback_, std::placeholders::_1),
        .onDestroy = std::bind(&ModalExtensionCallback::OnDestroy, uiExtCallback_),
    };

    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;

    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    IAM_LOGI("Create end, sessionId: %{public}d", sessionId);
    if (sessionId == 0) {
        IAM_LOGE("Create component failed, sessionId is 0");
        return false;
    }
    uiExtCallback_->SetSessionId(sessionId);
    return true;
}

void UserAuthModalCallback::CancelAuthentication(uint64_t contextId, int32_t cancelReason)
{
    // cancel for failed
    int32_t code = UserAuthNapiClientImpl::Instance().CancelAuthentication(contextId, cancelReason);
    IAM_LOGI("CancelAuthentication, code: %{public}d, contextId: ****%{public}hx, code: %{public}d", code,
        static_cast<uint16_t>(contextId), cancelReason);
    ReleaseModal();
}

void UserAuthModalCallback::ReleaseModal()
{
    // release modal widget
    if (uiExtCallback_ != nullptr) {
        IAM_LOGI("release modal");
        isInitError_ = true;
        uiExtCallback_->ReleaseOrErrorHandle(0);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
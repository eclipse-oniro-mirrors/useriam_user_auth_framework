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

#include "user_auth_napi_client_impl.h"

#include "system_ability_definition.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "ipc_client_utils.h"
#include "load_mode_client_util.h"
#include "modal_callback_service.h"
#include "user_auth_callback_service.h"
#include "user_auth_common_defines.h"

#define LOG_FILE_ID LOG_FILE_USER_AUTH_NAPI_CLIENT_IMPL
#define LOG_TAG "USER_AUTH_SDK"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
sptr<IUserAuth> UserAuthNapiClientImpl::GetProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> obj = IpcClientUtils::GetRemoteObject(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH);
    if (obj == nullptr) {
        IAM_LOGE("remote object is null");
        return proxy_;
    }
    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) UserAuthImplDeathRecipient());
    if ((dr == nullptr) || (obj->IsProxyObject() && !obj->AddDeathRecipient(dr))) {
        IAM_LOGE("add death recipient fail");
        return proxy_;
    }

    proxy_ = iface_cast<IUserAuth>(obj);
    deathRecipient_ = dr;
    return proxy_;
}

void UserAuthNapiClientImpl::ResetProxy(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        IAM_LOGE("proxy_ is null");
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        IAM_LOGI("need reset");
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
        deathRecipient_ = nullptr;
    }
    IAM_LOGI("end reset proxy");
}

void UserAuthNapiClientImpl::UserAuthImplDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    CallbackManager::GetInstance().OnServiceDeath();
    UserAuthNapiClientImpl::Instance().ResetProxy(remote);
}

UserAuthNapiClientImpl &UserAuthNapiClientImpl::Instance()
{
    static UserAuthNapiClientImpl impl;
    return impl;
}

uint64_t UserAuthNapiClientImpl::BeginWidgetAuth(int32_t apiVersion, const AuthParamInner &authParam,
    const WidgetParamNapi &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback,
    const std::shared_ptr<UserAuthModalClientCallback> &modalCallback)
{
    IAM_LOGI("start, apiVersion: %{public}d authTypeSize: %{public}zu authTrustLevel: %{public}u userId:%{public}d",
        apiVersion, authParam.authTypes.size(), authParam.authTrustLevel, authParam.userId);

    AuthParamInner authParamInner = {
        .userId = authParam.userId,
        .isUserIdSpecified = authParam.userId == INVALID_USER_ID ? false : true,
        .challenge = authParam.challenge,
        .authTypes = authParam.authTypes,
        .authTrustLevel = authParam.authTrustLevel,
        .reuseUnlockResult = authParam.reuseUnlockResult,
        .skipLockedBiometricAuth = authParam.skipLockedBiometricAuth,
        .credentialIdList = authParam.credentialIdList,
    };
    WidgetParamInner widgetParamInner = {
        .title = widgetParam.title,
        .navigationButtonText = widgetParam.navigationButtonText,
        .windowMode = widgetParam.windowMode,
        .hasContext = widgetParam.hasContext,
    };
    IAM_LOGI("has context: %{public}d", widgetParamInner.hasContext);
    return BeginWidgetAuthInner(apiVersion, authParamInner, widgetParamInner, callback, modalCallback);
}

uint64_t UserAuthNapiClientImpl::BeginWidgetAuthInner(int32_t apiVersion, const AuthParamInner &authParam,
    const WidgetParamInner &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback,
    const std::shared_ptr<UserAuthModalClientCallback> &modalCallback)
{
    if (!callback || !modalCallback) {
        IAM_LOGE("auth callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_BIOMETRIC_PERMISSION
        }));
        callback->OnResult(result, extraInfo);
        return BAD_CONTEXT_ID;
    }

    sptr<IIamCallback> wrapper(new (std::nothrow) UserAuthCallbackService(callback, modalCallback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
        return BAD_CONTEXT_ID;
    }

    // modal
    sptr<IModalCallback> wrapperModal(new (std::nothrow) ModalCallbackService(modalCallback));
    if (wrapperModal == nullptr) {
        IAM_LOGE("failed to create wrapper for modal");
        Attributes extraInfo;
        callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
        return BAD_CONTEXT_ID;
    }
    uint64_t contextId = BAD_CONTEXT_ID;
    IpcAuthParamInner ipcAuthParam = {};
    IpcWidgetParamInner ipcWidgetParam = {};
    InitIpcAuthParam(authParam, ipcAuthParam);
    InitIpcWidgetParam(widgetParam, ipcWidgetParam);
    auto ret = proxy->AuthWidget(apiVersion, ipcAuthParam, ipcWidgetParam, wrapper, wrapperModal, contextId);
    if (ret != SUCCESS) {
        IAM_LOGE("AuthWidget fail, ret:%{public}d", ret);
        return BAD_CONTEXT_ID;
    }
    return contextId;
}

int32_t UserAuthNapiClientImpl::CancelAuthentication(uint64_t contextId, int32_t cancelReason)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->CancelAuthOrIdentify(contextId, cancelReason);
}

void UserAuthNapiClientImpl::InitIpcAuthParam(const AuthParamInner &authParam,
    IpcAuthParamInner &ipcAuthParamInner)
{
    ipcAuthParamInner.userId = authParam.userId;
    ipcAuthParamInner.isUserIdSpecified = authParam.isUserIdSpecified;
    ipcAuthParamInner.challenge = authParam.challenge;
    ipcAuthParamInner.authType = static_cast<int32_t>(authParam.authType);
    ipcAuthParamInner.authTypes.resize(authParam.authTypes.size());
    std::transform(authParam.authTypes.begin(), authParam.authTypes.end(),
        ipcAuthParamInner.authTypes.begin(), [](AuthType authType) {
        return static_cast<int32_t>(authType);
    });
    ipcAuthParamInner.authTrustLevel = static_cast<int32_t>(authParam.authTrustLevel);
    ipcAuthParamInner.authIntent = static_cast<int32_t>(authParam.authIntent);
    ipcAuthParamInner.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    ipcAuthParamInner.credentialIdList = authParam.credentialIdList;
    ipcAuthParamInner.reuseUnlockResult.isReuse = authParam.reuseUnlockResult.isReuse;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = authParam.reuseUnlockResult.reuseMode;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = authParam.reuseUnlockResult.reuseDuration;
}

void UserAuthNapiClientImpl::InitIpcWidgetParam(const WidgetParamInner &widgetParam,
    IpcWidgetParamInner &ipcWidgetParamInner)
{
    ipcWidgetParamInner.title = widgetParam.title;
    ipcWidgetParamInner.navigationButtonText = widgetParam.navigationButtonText;
    ipcWidgetParamInner.windowMode = static_cast<int32_t>(widgetParam.windowMode);
    ipcWidgetParamInner.hasContext = widgetParam.hasContext;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

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

#include "user_access_ctrl_client_impl.h"

#include "system_ability_definition.h"

#include "callback_manager.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "ipc_client_utils.h"
#include "user_access_ctrl_callback_service.h"

#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_CLIENT_IMPL
#define LOG_TAG "USER_ACCESS_CTRL_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void UserAccessCtrlClientImpl::VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
    const std::shared_ptr<VerifyTokenCallback> &callback)
{
    IAM_LOGI("start");
    if (!callback) {
        IAM_LOGE("user access ctrl client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    sptr<IVerifyTokenCallback> wrapper(new (std::nothrow) VerifyTokenCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    proxy->VerifyAuthToken(tokenIn, allowableDuration, wrapper);
}

sptr<IUserAuth> UserAccessCtrlClientImpl::GetProxy()
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
    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) UserAccessCtrlImplDeathRecipient());
    if ((dr == nullptr) || (obj->IsProxyObject() && !obj->AddDeathRecipient(dr))) {
        IAM_LOGE("add death recipient fail");
        return proxy_;
    }

    proxy_ = iface_cast<IUserAuth>(obj);
    deathRecipient_ = dr;
    return proxy_;
}

void UserAccessCtrlClientImpl::ResetProxy(const wptr<IRemoteObject> &remote)
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

void UserAccessCtrlClientImpl::UserAccessCtrlImplDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    CallbackManager::GetInstance().OnServiceDeath();
    UserAccessCtrlClientImpl::Instance().ResetProxy(remote);
}

UserAccessCtrlClientImpl &UserAccessCtrlClientImpl::Instance()
{
    static UserAccessCtrlClientImpl impl;
    return impl;
}

UserAccessCtrlClient &UserAccessCtrlClient::GetInstance()
{
    return UserAccessCtrlClientImpl::Instance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
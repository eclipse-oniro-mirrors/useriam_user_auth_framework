/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "co_auth_client_impl.h"

#include "system_ability_definition.h"

#include "callback_manager.h"
#include "executor_callback_service.h"
#include "iam_logger.h"
#include "ipc_client_utils.h"

#define LOG_TAG "EXECUTOR_MGR_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void CoAuthClientImpl::Register(const ExecutorInfo &info, const std::shared_ptr<ExecutorRegisterCallback> &callback)
{
    IAM_LOGI("start type:%{public}d role:%{public}d", info.authType, info.executorRole);
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        return;
    }

    CoAuthInterface::ExecutorRegisterInfo regInfo;
    regInfo.authType = info.authType;
    regInfo.executorRole = info.executorRole;
    regInfo.executorSensorHint = info.executorSensorHint;
    regInfo.executorMatcher = info.executorMatcher;
    regInfo.esl = info.esl;
    regInfo.publicKey = info.publicKey;
    regInfo.deviceUdid = info.deviceUdid;
    regInfo.signedRemoteExecutorInfo = info.signedRemoteExecutorInfo;
    regInfo.maxTemplateAcl = info.maxTemplateAcl;
    sptr<ExecutorCallbackInterface> wrapper(new (std::nothrow) ExecutorCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return;
    }
    proxy->ExecutorRegister(regInfo, wrapper);
}

void CoAuthClientImpl::Unregister(uint64_t executorIndex)
{
    IAM_LOGI("start");

    auto proxy = GetProxy();
    if (!proxy) {
        return;
    }

    proxy->ExecutorUnregister(executorIndex);
}

sptr<CoAuthInterface> CoAuthClientImpl::GetProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> obj = IpcClientUtils::GetRemoteObject(SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR);
    if (obj == nullptr) {
        IAM_LOGE("remote object is null");
        return proxy_;
    }
    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) CoAuthImplDeathRecipient());
    if ((dr == nullptr) || (obj->IsProxyObject() && !obj->AddDeathRecipient(dr))) {
        IAM_LOGE("add death recipient fail");
        return proxy_;
    }

    proxy_ = iface_cast<CoAuthInterface>(obj);
    deathRecipient_ = dr;
    return proxy_;
}

void CoAuthClientImpl::ResetProxy(const wptr<IRemoteObject> &remote)
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

void CoAuthClientImpl::CoAuthImplDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    CallbackManager::GetInstance().OnServiceDeath();
    CoAuthClientImpl::Instance().ResetProxy(remote);
}

CoAuthClientImpl &CoAuthClientImpl::Instance()
{
    static CoAuthClientImpl impl;
    return impl;
}

CoAuthClient &CoAuthClient::GetInstance()
{
    return CoAuthClientImpl::Instance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
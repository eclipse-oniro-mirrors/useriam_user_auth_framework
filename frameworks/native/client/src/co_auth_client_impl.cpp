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
#define LOG_FILE_ID LOG_FILE_CO_AUTH_CLIENT_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void CoAuthClientImpl::InitIpcExecutorInfo(const ExecutorInfo &info, IpcExecutorRegisterInfo &ipcExecutorRegisterInfo)
{
    ipcExecutorRegisterInfo.authType = static_cast<int32_t>(info.authType);
    ipcExecutorRegisterInfo.executorRole = static_cast<int32_t>(info.executorRole);
    ipcExecutorRegisterInfo.executorSensorHint = static_cast<uint32_t>(info.executorSensorHint);
    ipcExecutorRegisterInfo.executorMatcher = static_cast<uint32_t>(info.executorMatcher);
    ipcExecutorRegisterInfo.esl = static_cast<int32_t>(info.esl);
    ipcExecutorRegisterInfo.publicKey = info.publicKey;
    ipcExecutorRegisterInfo.deviceUdid = info.deviceUdid;
    ipcExecutorRegisterInfo.signedRemoteExecutorInfo = info.signedRemoteExecutorInfo;
    ipcExecutorRegisterInfo.maxTemplateAcl = static_cast<uint32_t>(info.maxTemplateAcl);
}

uint64_t CoAuthClientImpl::Register(const ExecutorInfo &info, const std::shared_ptr<ExecutorRegisterCallback> &callback)
{
    IAM_LOGI("start type:%{public}d role:%{public}d", info.authType, info.executorRole);
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return INVALID_EXECUTOR_INDEX;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        return INVALID_EXECUTOR_INDEX;
    }

    IpcExecutorRegisterInfo regInfo = {};
    InitIpcExecutorInfo(info, regInfo);
    sptr<IExecutorCallback> wrapper(new (std::nothrow) ExecutorCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return INVALID_EXECUTOR_INDEX;
    }
    uint64_t executorIndex = INVALID_EXECUTOR_INDEX;
    auto ret = proxy->ExecutorRegister(regInfo, wrapper, executorIndex);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("executor register fail, ret:%{public}d, type: %{public}d role: %{public}d, "
            "esl: %{public}d, acl: %{public}d", ret, info.authType, info.executorRole, info.esl, info.maxTemplateAcl);
        return INVALID_EXECUTOR_INDEX;
    }

    return executorIndex;
}

void CoAuthClientImpl::Unregister(uint64_t executorIndex)
{
    IAM_LOGI("start");

    auto proxy = GetProxy();
    if (!proxy) {
        return;
    }

    auto ret = proxy->ExecutorUnregister(executorIndex);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("executor unregister fail, ret:%{public}d, executorInd: ****%{public}hx",
            ret, static_cast<uint16_t>(executorIndex));
        return;
    }
}

sptr<ICoAuth> CoAuthClientImpl::GetProxy()
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

    proxy_ = iface_cast<ICoAuth>(obj);
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
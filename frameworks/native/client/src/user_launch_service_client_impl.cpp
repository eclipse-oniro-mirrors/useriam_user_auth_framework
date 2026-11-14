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

#include "user_launch_service_client_impl.h"

#include "user_launch_service_callback_service.h"

#include "callback_manager.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "system_ability_definition.h"

#define LOG_TAG "USER_LAUNCH_SERVICE_SDK"
#define LOG_FILE_ID LOG_FILE_USER_LAUNCH_SERVICE_CLIENT_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {

UserLaunchServiceImpl &UserLaunchServiceImpl::Instance()
{
    static UserLaunchServiceImpl impl;
    return impl;
}

UserLaunchServiceClient &UserLaunchServiceClient::GetInstance()
{
    return UserLaunchServiceImpl::Instance();
}

void UserLaunchServiceImpl::UserLaunchServiceDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN(remote != nullptr);
    CallbackManager::GetInstance().OnServiceDeath();
    UserLaunchServiceImpl::Instance().ResetProxy(remote);
}

sptr<IUserAuth> UserLaunchServiceImpl::GetProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<IRemoteObject> obj = IpcClientUtils::GetRemoteObject(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH);
    IF_FALSE_LOGE_AND_RETURN_VAL(obj != nullptr, proxy_);

    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) UserLaunchServiceDeathRecipient());
    IF_FALSE_LOGE_AND_RETURN_VAL(dr != nullptr, proxy_);
    IF_FALSE_LOGE_AND_RETURN_VAL((!obj->IsProxyObject() || obj->AddDeathRecipient(dr)), proxy_);

    proxy_ = iface_cast<IUserAuth>(obj);
    deathRecipient_ = dr;
    return proxy_;
}

void UserLaunchServiceImpl::ResetProxy(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    IF_FALSE_LOGE_AND_RETURN(proxy_ != nullptr);

    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        IAM_LOGI("need reset");
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
        deathRecipient_ = nullptr;
    }
}

void UserLaunchServiceImpl::RegisterLaunchService(const std::vector<LaunchServiceRegisterInfo> &serviceList,
    const std::shared_ptr<LaunchServiceListCallback> &callback)
{
    IAM_LOGI("start, serviceCount:%{public}zu", serviceList.size());
    if (callback == nullptr) {
        IAM_LOGE("register launch service callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        IAM_LOGE("proxy is nullptr");
        callback->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        return;
    }

    sptr<ILaunchServiceListCallback> wrapper(
        new (std::nothrow) LaunchServiceListCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        callback->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        return;
    }

    std::vector<IpcLaunchServiceRegisterInfo> ipcList = {};
    ipcList.reserve(serviceList.size());
    for (const auto &info : serviceList) {
        IpcLaunchServiceRegisterInfo ipcInfo;
        ipcInfo.uid = info.uid;
        ipcInfo.serviceKey = IpcLaunchServiceKey{info.serviceKey.serviceName, info.serviceKey.moduleName};
        ipcInfo.bundleInfo = IpcBundleExtInfo{info.bundleInfo.ownerBundleName,
            info.bundleInfo.appIndex, info.bundleInfo.appIdentifier};
        ipcInfo.serviceInfo = IpcServiceExtInfo{static_cast<int32_t>(info.serviceInfo.serviceType),
            info.serviceInfo.additionalInfo};
        ipcList.push_back(std::move(ipcInfo));
    }
    int32_t ret = proxy->RegisterLaunchService(ipcList, wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        callback->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        return;
    }
}

void UserLaunchServiceImpl::UnRegisterLaunchService(int32_t uid, const std::optional<LaunchServiceKey> &key,
    const std::shared_ptr<LaunchServiceCallback> &callback)
{
    IAM_LOGI("start, uid:%{public}d, hasKey:%{public}d", uid, key.has_value());
    if (callback == nullptr) {
        IAM_LOGE("unregister launch service callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        IAM_LOGE("proxy is nullptr");
        callback->OnResult(GENERAL_ERROR);
        return;
    }

    sptr<ILaunchServiceCallback> wrapper(
        new (std::nothrow) LaunchServiceCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        callback->OnResult(GENERAL_ERROR);
        return;
    }

    IpcLaunchServiceKey ipcKey = {};
    if (key.has_value()) {
        ipcKey = IpcLaunchServiceKey{ key.value().serviceName, key.value().moduleName };
    }
    int32_t ret = proxy->UnRegisterLaunchService(uid, key.has_value(), ipcKey, wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        callback->OnResult(GENERAL_ERROR);
        return;
    }
}

void UserLaunchServiceImpl::GetLaunchServiceInfo(int32_t uid, const std::optional<LaunchServiceKey> &key,
    const std::shared_ptr<LaunchServiceListCallback> &callback)
{
    IAM_LOGI("start, uid:%{public}d, hasKey:%{public}d", uid, key.has_value());
    if (callback == nullptr) {
        IAM_LOGE("get launch service info callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        IAM_LOGE("proxy is nullptr");
        callback->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        return;
    }

    sptr<ILaunchServiceListCallback> wrapper(
        new (std::nothrow) LaunchServiceListCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        callback->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        return;
    }

    IpcLaunchServiceKey ipcKey = {};
    if (key.has_value()) {
        ipcKey = IpcLaunchServiceKey{ key.value().serviceName, key.value().moduleName };
    }
    int32_t ret = proxy->GetLaunchServiceInfo(uid, key.has_value(), ipcKey, wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        callback->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        return;
    }
}

void UserLaunchServiceImpl::GetLaunchServiceList(const std::optional<int32_t> &userId,
    const std::shared_ptr<LaunchServiceListCallback> &callback)
{
    IAM_LOGI("start %{public}d", userId.has_value());
    if (callback == nullptr) {
        IAM_LOGE("get launch service list callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        IAM_LOGE("proxy is nullptr");
        callback->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        return;
    }

    sptr<ILaunchServiceListCallback> wrapper(
        new (std::nothrow) LaunchServiceListCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        callback->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        return;
    }

    int32_t userIdVal = userId.has_value() ? userId.value() : INVALID_USER_ID;
    int32_t ret = proxy->GetLaunchServiceList(userId.has_value(), userIdVal, wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        callback->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        return;
    }
}

void UserLaunchServiceImpl::SetLaunchServiceState(int32_t uid, const std::vector<uint8_t> &token,
    LaunchServiceState activeState, const std::shared_ptr<LaunchServiceCallback> &callback)
{
    IAM_LOGI("start, uid:%{public}d, state:%{public}d", uid, static_cast<int32_t>(activeState));
    if (callback == nullptr) {
        IAM_LOGE("set launch service state callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        IAM_LOGE("proxy is nullptr");
        callback->OnResult(GENERAL_ERROR);
        return;
    }

    sptr<ILaunchServiceCallback> wrapper(
        new (std::nothrow) LaunchServiceCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        callback->OnResult(GENERAL_ERROR);
        return;
    }

    int32_t ret = proxy->SetLaunchServiceState(uid, token, static_cast<int32_t>(activeState), wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        callback->OnResult(GENERAL_ERROR);
        return;
    }
}
int32_t UserLaunchServiceImpl::SetDaemonAllowedlist(int32_t userId, const std::vector<std::string> &appIdentifiers,
    bool isAdd)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    auto proxy = GetProxy();
    IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);

    int32_t funcRet = SUCCESS;
    int32_t ret = proxy->SetDaemonAllowedlist(userId, appIdentifiers, isAdd, funcRet);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }
    return funcRet;
}

int32_t UserLaunchServiceImpl::SetDaemonForbiddenlist(int32_t userId,
    const std::vector<std::string> &appIdentifiers, bool isAdd)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    auto proxy = GetProxy();
    IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);

    int32_t funcRet = SUCCESS;
    int32_t ret = proxy->SetDaemonForbiddenlist(userId, appIdentifiers, isAdd, funcRet);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }
    return funcRet;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

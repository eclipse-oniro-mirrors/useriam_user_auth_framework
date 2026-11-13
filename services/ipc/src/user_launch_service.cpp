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

#include "user_auth_service.h"

#include <future>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "attributes.h"
#include "authorization_callback.h"
#include "authorization_client.h"
#include "context_callback.h"
#include "context_factory.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_defines.h"
#include "iam_logger.h"
#include "ipc_common.h"
#include "thread_handler_manager.h"
#include "user_auth_common_defines.h"
#include "user_auth_engine.h"
#include "user_launch_service_client_defines.h"
#include "xcollie_helper.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_USER_LAUNCH_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class AuthWidgetResultCallback : public IIamCallback, public NoCopyable {
public:
    explicit AuthWidgetResultCallback(std::shared_ptr<std::promise<int32_t>> promise) : promise_(promise) {}
    ~AuthWidgetResultCallback() override = default;

    int32_t OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo) override
    {
        IAM_LOGI("launch service auth widget result: %{public}d", resultCode);
        if (resultCode == SUCCESS) {
            Attributes attr(extraInfo);
            attr.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token_);
        }
        if (promise_ != nullptr) {
            promise_->set_value(resultCode);
        }
        return SUCCESS;
    }

    int32_t OnAcquireInfo(int32_t module, int32_t acquireInfo,
        const std::vector<uint8_t> &extraInfo) override
    {
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    std::vector<uint8_t> &GetToken()
    {
        return token_;
    }

private:
    std::shared_ptr<std::promise<int32_t>> promise_;
    std::vector<uint8_t> token_ {};
};

class AdminAuthResultCallback : public AccountSA::AuthorizationCallback, public NoCopyable {
public:
    explicit AdminAuthResultCallback(std::shared_ptr<std::promise<int32_t>> promise) : promise_(promise) {}
    ~AdminAuthResultCallback() override = default;

    ErrCode OnResult(int32_t resultCode, const AccountSA::AuthorizationResult &result) override
    {
        IAM_LOGI("launch service auth admin result: %{public}d,%{public}d", resultCode, result.resultCode);
        int32_t authResult = GENERAL_ERROR;
        if (resultCode == 0 &&
            result.resultCode == AccountSA::AuthorizationResultCode::AUTHORIZATION_SUCCESS) {
            authResult = SUCCESS;
            token_ = result.token;
        }
        if (promise_ != nullptr) {
            promise_->set_value(authResult);
        }
        return SUCCESS;
    }

    ErrCode OnConnectAbility(const AccountSA::ConnectAbilityInfo &info, const sptr<IRemoteObject> &callback) override
    {
        return SUCCESS;
    }

    std::vector<uint8_t> &GetToken()
    {
        return token_;
    }

private:
    std::shared_ptr<std::promise<int32_t>> promise_;
    std::vector<uint8_t> token_ {};
};

EngLaunchServiceState ConvertToEngLaunchServiceState(int32_t activeState, EngLaunchServiceType serviceType)
{
    if (static_cast<LaunchServiceState>(activeState) != LaunchServiceState::ACTIVATE) {
        return EngLaunchServiceState::INVALID;
    }
    return serviceType == EngLaunchServiceType::PRIVILEGED_DAEMON
        ? EngLaunchServiceState::DAEMON_ACTIVE
        : EngLaunchServiceState::AGENT_ACTIVE;
}

int32_t ConvertFromEngLaunchServiceState(EngLaunchServiceState state)
{
    return state == EngLaunchServiceState::INVALID
        ? static_cast<int32_t>(LaunchServiceState::DEACTIVATE)
        : static_cast<int32_t>(LaunchServiceState::ACTIVATE);
}
} // namespace
IpcLaunchServiceFlatInfo UserAuthService::ConvertToIpcLaunchServiceFlatInfo(const EngLaunchServiceFlatInfo &info)
{
    IpcLaunchServiceFlatInfo ipcInfo = {};
    ipcInfo.uid = info.uid;
    ipcInfo.serviceKey = IpcLaunchServiceKey{info.serviceKey.serviceName, info.serviceKey.moduleName};
    ipcInfo.bundleInfo = IpcBundleExtInfo{info.bundleInfo.ownerBundleName,
        info.bundleInfo.appIndex, info.bundleInfo.appIdentifier};
    ipcInfo.serviceInfo = IpcServiceExtInfo{static_cast<int32_t>(info.serviceInfo.serviceType),
        info.serviceInfo.additionalInfo};
    ipcInfo.activeState = ConvertFromEngLaunchServiceState(info.activeState);
    ipcInfo.isForbidden = info.isForbidden;
    ipcInfo.launchServiceSize = info.launchServiceSize;
    return ipcInfo;
}

EngLaunchServiceRegisterInfo UserAuthService::ConvertFromIpcLaunchServiceRegisterInfo(
    const IpcLaunchServiceRegisterInfo &ipcInfo)
{
    EngLaunchServiceRegisterInfo info = {};
    info.uid = ipcInfo.uid;
    info.serviceKey = EngLaunchServiceKey{ipcInfo.serviceKey.serviceName, ipcInfo.serviceKey.moduleName};
    info.bundleInfo = EngBundleExtInfo{ipcInfo.bundleInfo.ownerBundleName,
        ipcInfo.bundleInfo.appIndex, ipcInfo.bundleInfo.appIdentifier};
    info.serviceInfo = EngServiceExtInfo{static_cast<EngLaunchServiceType>(ipcInfo.serviceInfo.serviceType),
        ipcInfo.serviceInfo.additionalInfo};
    return info;
}

int32_t UserAuthService::RegisterLaunchServiceInner(const std::vector<IpcLaunchServiceRegisterInfo> &serviceList,
    std::vector<IpcLaunchServiceFlatInfo> &serviceInfos)
{
    if (serviceList.empty()) {
        IAM_LOGE("empty serviceList");
        return INVALID_PARAMETERS;
    }

    std::vector<EngLaunchServiceRegisterInfo> engineList = {};
    for (const auto &ipcInfo : serviceList) {
        engineList.push_back(ConvertFromIpcLaunchServiceRegisterInfo(ipcInfo));
    }

    std::vector<EngLaunchServiceFlatInfo> engineInfos = {};
    int32_t funcRet = GetUserAuthEngine().RegisterLaunchService(engineList, engineInfos);
    if (funcRet != SUCCESS) {
        IAM_LOGE("failed to register launch service, result:%{public}d", funcRet);
    }
    for (const auto &info : engineInfos) {
        serviceInfos.push_back(ConvertToIpcLaunchServiceFlatInfo(info));
    }
    return funcRet;
}

int32_t UserAuthService::UnRegisterLaunchServiceInner(int32_t uid, const std::optional<IpcLaunchServiceKey> &key)
{
    std::optional<EngLaunchServiceKey> engineKey = {};
    if (key.has_value()) {
        if (key->serviceName.empty() || key->moduleName.empty()) {
            IAM_LOGE("invalid serviceName or moduleName");
            return INVALID_PARAMETERS;
        }
        engineKey = EngLaunchServiceKey{key->serviceName, key->moduleName};
    }
    return GetUserAuthEngine().UnRegisterLaunchService(uid, engineKey);
}

int32_t UserAuthService::GetLaunchServiceInfoInner(int32_t uid, const std::optional<IpcLaunchServiceKey> &key,
    std::vector<IpcLaunchServiceFlatInfo> &serviceList)
{
    std::optional<EngLaunchServiceKey> engineKey = {};
    if (key.has_value()) {
        if (key->serviceName.empty() || key->moduleName.empty()) {
            IAM_LOGE("invalid serviceName or moduleName");
            return INVALID_PARAMETERS;
        }
        engineKey = EngLaunchServiceKey{key->serviceName, key->moduleName};
    }

    std::vector<EngLaunchServiceFlatInfo> engineList = {};
    int32_t funcRet = GetUserAuthEngine().GetLaunchServiceInfo(uid, engineKey, engineList);
    if (funcRet != SUCCESS) {
        IAM_LOGE("failed to get launch service info, result:%{public}d", funcRet);
        return funcRet;
    }
    for (const auto &info : engineList) {
        serviceList.push_back(ConvertToIpcLaunchServiceFlatInfo(info));
    }
    return SUCCESS;
}

int32_t UserAuthService::GetLaunchServiceListInner(std::optional<int32_t> optUserId,
    std::vector<IpcLaunchServiceFlatInfo> &serviceList)
{
    std::vector<int32_t> userIdList = {};
    if (optUserId.has_value()) {
        userIdList.push_back(optUserId.value());
    } else {
        int32_t ret = IpcCommon::GetAllUserId(userIdList);
        if (ret != SUCCESS) {
            IAM_LOGE("GetAllUserId failed");
            return IPC_ERROR;
        }
    }

    if (userIdList.empty()) {
        IAM_LOGI("launch service userIdList is empty");
        return SUCCESS;
    }

    std::vector<EngLaunchServiceFlatInfo> serviceListVal = {};
    int32_t funcRet = GetUserAuthEngine().GetLaunchServiceList(userIdList, serviceListVal);
    if (funcRet != SUCCESS) {
        IAM_LOGE("failed to get launch service list, result:%{public}d", funcRet);
        return funcRet;
    }
    for (const auto &info : serviceListVal) {
        serviceList.push_back(ConvertToIpcLaunchServiceFlatInfo(info));
    }
    return SUCCESS;
}

int32_t UserAuthService::RegisterLaunchService(const std::vector<IpcLaunchServiceRegisterInfo> &serviceList,
    const sptr<ILaunchServiceListCallback> &launchServiceCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(launchServiceCallback != nullptr, INVALID_PARAMETERS);
    if (!IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER)) {
        IAM_LOGE("failed to check permission");
        launchServiceCallback->OnLaunchServiceListResult(CHECK_PERMISSION_FAILED,
            std::vector<IpcLaunchServiceFlatInfo>{});
        return SUCCESS;
    }

    ThreadHandlerManager::GetInstance().PostTaskOnTemporaryThread("RegisterLaunchService",
        [this, serviceList, launchServiceCallback]() {
            std::vector<IpcLaunchServiceFlatInfo> serviceInfos = {};
            int32_t ret = RegisterLaunchServiceInner(serviceList, serviceInfos);
            launchServiceCallback->OnLaunchServiceListResult(ret, serviceInfos);
        });
    return SUCCESS;
}

int32_t UserAuthService::UnRegisterLaunchService(int32_t uid, bool hasKey, const IpcLaunchServiceKey &key,
    const sptr<ILaunchServiceCallback> &launchServiceCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(launchServiceCallback != nullptr, INVALID_PARAMETERS);
    if (!IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER)) {
        IAM_LOGE("failed to check permission");
        launchServiceCallback->OnLaunchServiceResult(CHECK_PERMISSION_FAILED);
        return SUCCESS;
    }

    std::optional<IpcLaunchServiceKey> optKey = hasKey ? std::optional<IpcLaunchServiceKey>(key) : std::nullopt;
    ThreadHandlerManager::GetInstance().PostTaskOnTemporaryThread("UnRegisterLaunchService",
        [this, uid, optKey, launchServiceCallback]() {
            int32_t funcRet = UnRegisterLaunchServiceInner(uid, optKey);
            launchServiceCallback->OnLaunchServiceResult(funcRet);
        });
    return SUCCESS;
}

int32_t UserAuthService::GetLaunchServiceInfo(int32_t uid, bool hasKey, const IpcLaunchServiceKey &key,
    const sptr<ILaunchServiceListCallback> &launchServiceCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(launchServiceCallback != nullptr, INVALID_PARAMETERS);
    if (!IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER)) {
        IAM_LOGE("failed to check permission");
        launchServiceCallback->OnLaunchServiceListResult(CHECK_PERMISSION_FAILED,
            std::vector<IpcLaunchServiceFlatInfo>{});
        return SUCCESS;
    }

    std::optional<IpcLaunchServiceKey> optKey = hasKey ? std::optional<IpcLaunchServiceKey>(key) : std::nullopt;
    ThreadHandlerManager::GetInstance().PostTaskOnTemporaryThread("GetLaunchServiceInfo",
        [this, uid, optKey, launchServiceCallback]() {
            std::vector<IpcLaunchServiceFlatInfo> serviceList = {};
            int32_t ret = GetLaunchServiceInfoInner(uid, optKey, serviceList);
            launchServiceCallback->OnLaunchServiceListResult(ret, serviceList);
        });
    return SUCCESS;
}

int32_t UserAuthService::GetLaunchServiceList(bool hasUserId, int32_t userId,
    const sptr<ILaunchServiceListCallback> &launchServiceCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(launchServiceCallback != nullptr, INVALID_PARAMETERS);
    if (!IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER)) {
        IAM_LOGE("failed to check permission");
        launchServiceCallback->OnLaunchServiceListResult(CHECK_PERMISSION_FAILED,
            std::vector<IpcLaunchServiceFlatInfo>{});
        return SUCCESS;
    }
    std::optional<int32_t> optUserId = hasUserId ? std::optional<int32_t>(userId) : std::nullopt;

    ThreadHandlerManager::GetInstance().PostTaskOnTemporaryThread("GetLaunchServiceList",
        [this, optUserId, launchServiceCallback]() {
            std::vector<IpcLaunchServiceFlatInfo> serviceList = {};
            int32_t ret = GetLaunchServiceListInner(optUserId, serviceList);
            launchServiceCallback->OnLaunchServiceListResult(ret, serviceList);
        });
    return SUCCESS;
}

int32_t UserAuthService::AuthWidgetForToken(ContextFactory::AuthWidgetContextPara &para,
    std::vector<uint8_t> &authToken)
{
    IAM_LOGI("start launch service auth for token, userId:%{public}d", para.userId);
    auto promise = std::make_shared<std::promise<int32_t>>();
    auto future = promise->get_future();

    sptr<AuthWidgetResultCallback> iamCallback = new (std::nothrow) AuthWidgetResultCallback(promise);
    IF_FALSE_LOGE_AND_RETURN_VAL(iamCallback != nullptr, GENERAL_ERROR);

    auto contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_AUTH_USER_BEHAVIOR);
    IF_FALSE_LOGE_AND_RETURN_VAL(contextCallback != nullptr, GENERAL_ERROR);

    para.isBackgroundApplication = true;
    para.authTypeList = {PIN};
    para.atl = ATL3;
    para.widgetParam.windowMode = UNKNOWN_WINDOW_MODE;
    para.sdkVersion = INNER_API_VERSION_20000;
    ReuseUnlockResult reuseUnlockResult = {};
    SetAuthWidgetContextTrace(para, reuseUnlockResult, contextCallback);

    uint64_t contextId = BAD_CONTEXT_ID;
    int32_t ret = StartAuthWidget(para, contextCallback, nullptr, contextId);
    if (ret != SUCCESS) {
        IAM_LOGE("StartAuthWidget fail, ret:%{public}d", ret);
        return ret;
    }

    int32_t resultCode = future.get();
    authToken = iamCallback->GetToken();
    if (resultCode != SUCCESS) {
        IAM_LOGE("auth widget result:%{public}d", resultCode);
        return resultCode;
    }
    if (authToken.empty()) {
        IAM_LOGE("auth widget result:%{public}d, tokenSize:%{public}zu", resultCode, authToken.size());
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthService::AdminAuthForToken(int32_t uid, std::vector<uint8_t> &authToken)
{
    IAM_LOGI("start launch service auth for token");
    auto promise = std::make_shared<std::promise<int32_t>>();
    auto future = promise->get_future();

    auto callback = std::make_shared<AdminAuthResultCallback>(promise);
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, GENERAL_ERROR);

    int32_t pid = 0;
    if (!IpcCommon::GetRunningAppPid(uid, pid)) {
        IAM_LOGE("failed to get running app pid, uid:%{public}d", uid);
        return GENERAL_ERROR;
    }

    AccountSA::SubjectInfo accountInfo = {};
    accountInfo.pid = pid;
    accountInfo.uid = uid;
    AccountSA::AcquireAuthorizationOptions options = {};
    options.challenge = {};
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;
    options.subjectInfo = std::make_optional(accountInfo);

    std::string privilege = "ohos.privilege.manage_enterprise_device_management_applications";
    ErrCode errRet = AccountSA::AuthorizationClient::GetInstance().AcquireAuthorization(
        privilege, options, callback);
    if (errRet != 0) {
        IAM_LOGE("AcquireAuthorization failed, err:%{public}d", errRet);
        return GENERAL_ERROR;
    }

    int32_t resultCode = future.get();
    authToken = callback->GetToken();
    if (resultCode != SUCCESS) {
        IAM_LOGE("admin auth result:%{public}d", resultCode);
        return GENERAL_ERROR;
    }
    if (authToken.empty()) {
        IAM_LOGE("admin auth token is empty");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthService::GetAuthToken(EngLaunchServiceType serviceType, int32_t uid,
    ContextFactory::AuthWidgetContextPara &para, std::vector<uint8_t> &authToken)
{
    if (!authToken.empty()) {
        return SUCCESS;
    }
    if (serviceType == EngLaunchServiceType::PRIVILEGED_DAEMON) {
        return AdminAuthForToken(uid, authToken);
    }
    return AuthWidgetForToken(authPara, authToken);
}

int32_t UserAuthService::SetLaunchServiceState(int32_t uid, const std::vector<uint8_t> &token,
    int32_t activeState, const sptr<ILaunchServiceCallback> &launchServiceCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(launchServiceCallback != nullptr, INVALID_PARAMETERS);
    if (!IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER)) {
        IAM_LOGE("failed to check permission");
        launchServiceCallback->OnLaunchServiceResult(CHECK_PERMISSION_FAILED);
        return SUCCESS;
    }

    ContextFactory::AuthWidgetContextPara para = {};
    static_cast<void>(IpcCommon::GetCallerName(*this, para.callerName, para.callerType));
    if (para.callerType == Security::AccessToken::TOKEN_HAP &&
        !IpcCommon::CheckForegroundApplication(para.callerName)) {
        IAM_LOGE("failed to CheckForegroundApplication");
        launchServiceCallback->OnLaunchServiceResult(CHECK_PERMISSION_FAILED);
        return SUCCESS;
    }

    static_cast<void>(IpcCommon::GetCallingAppID(*this, para.callingAppID, para.callingAppIdentifier));
    para.userId = uid / CONVERT_UID_TO_USERID;
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    ThreadHandlerManager::GetInstance().PostTaskOnTemporaryThread("SetLaunchServiceState",
        [this, uid, token, activeState, launchServiceCallback, para]() {
            EngLaunchServiceType serviceType = EngLaunchServiceType::INVALID;
            int32_t ret = GetUserAuthEngine().GetAppLaunchServiceType(uid, serviceType);
            if (ret != SUCCESS) {
                launchServiceCallback->OnLaunchServiceResult(ret);
                return;
            }
            ret = GetAuthToken(serviceType, uid, para, authToken);
            if (ret != SUCCESS) {
                launchServiceCallback->OnLaunchServiceResult(ret);
                return;
            }
            EngLaunchServiceState engineState = ConvertToEngLaunchServiceState(activeState, serviceType);
            ret = GetUserAuthEngine().SetLaunchServiceState(uid, token, engineState);
            launchServiceCallback->OnLaunchServiceResult(ret);
        });
    return SUCCESS;
}

int32_t UserAuthService::SetDaemonAllowedlist(int32_t userId, const std::vector<std::string> &appIdentifiers,
    bool isAdd, int32_t &funcRet)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (!IpcCommon::CheckPermission(*this, ENTERPRISE_DEVICE_MGR)) {
        IAM_LOGE("failed to check permission");
        funcRet = CHECK_PERMISSION_FAILED;
        return SUCCESS;
    }

    funcRet = GetUserAuthEngine().SetDaemonAllowedlist(userId, appIdentifiers, isAdd);
    return SUCCESS;
}

int32_t UserAuthService::SetDaemonForbiddenlist(int32_t userId, const std::vector<std::string> &appIdentifiers,
    bool isAdd, int32_t &funcRet)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (!IpcCommon::CheckPermission(*this, ENTERPRISE_DEVICE_MGR)) {
        IAM_LOGE("failed to check permission");
        funcRet = CHECK_PERMISSION_FAILED;
        return SUCCESS;
    }

    funcRet = GetUserAuthEngine().SetDaemonForbiddenlist(userId, appIdentifiers, isAdd);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

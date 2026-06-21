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

#include "user_auth_client_impl.h"

#include "remote_auth_callback_service.h"
#include "system_ability_definition.h"

#include "auth_common.h"
#include "callback_manager.h"
#include "load_mode_client_util.h"
#include "iam_check.h"
#include "iam_defines.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "ipc_client_utils.h"
#include "modal_callback_service.h"
#include "user_auth_callback_service.h"
#include "user_auth_modal_inner_callback.h"
#include "widget_callback_service.h"

#define LOG_TAG "USER_AUTH_SDK"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const uint32_t MAX_ATTR_COUNT = 512;
class NorthAuthenticationCallback : public AuthenticationCallback, public NoCopyable {
public:
    explicit NorthAuthenticationCallback(std::shared_ptr<AuthenticationCallback> innerCallback);
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    std::shared_ptr<AuthenticationCallback> innerCallback_ = nullptr;
};

NorthAuthenticationCallback::NorthAuthenticationCallback(std::shared_ptr<AuthenticationCallback> innerCallback)
    : innerCallback_(innerCallback) {};

void NorthAuthenticationCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    if (module == AuthType::FACE) {
        if (acquireInfo == 0 || acquireInfo > FACE_AUTH_TIP_MAX) {
            IAM_LOGI("skip undefined face auth tip %{public}u", acquireInfo);
            return;
        }
    } else if (module == AuthType::FINGERPRINT) {
        if (acquireInfo > FINGERPRINT_AUTH_TIP_MAX) {
            IAM_LOGI("skip undefined fingerprint auth tip %{public}u", acquireInfo);
            return;
        }
    }

    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

void NorthAuthenticationCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    innerCallback_->OnResult(result, extraInfo);
}
} // namespace

int32_t UserAuthClientImpl::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start, authType:%{public}d authTrustLevel:%{public}u", authType, authTrustLevel);
    auto proxy = GetProxy();
    if (!proxy) {
        return LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_USER_AUTH_INTERNAL_PERMISSION,
            ACCESS_BIOMETRIC_PERMISSION
        }));
    }

    int32_t funcResult = SUCCESS;
    int32_t ret = proxy->GetAvailableStatus(INNER_API_VERSION_10000, static_cast<int32_t>(authType),
        static_cast<uint32_t>(authTrustLevel), funcResult);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }
    if (funcResult != SUCCESS) {
        IAM_LOGI("service call return fail, ret:%{public}d", funcResult);
        return funcResult;
    }
    return SUCCESS;
}

int32_t UserAuthClientImpl::GetNorthAvailableStatus(int32_t apiVersion, AuthType authType,
    AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start, apiVersion:%{public}d authType:%{public}d authTrustLevel:%{public}u",
        apiVersion, authType, authTrustLevel);
    auto proxy = GetProxy();
    if (!proxy) {
        return LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_USER_AUTH_INTERNAL_PERMISSION,
            ACCESS_BIOMETRIC_PERMISSION
        }));
    }
    int32_t funcResult = SUCCESS;
    int32_t ret = proxy->GetAvailableStatus(apiVersion, static_cast<int32_t>(authType),
        static_cast<uint32_t>(authTrustLevel), funcResult);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }
    if (funcResult != SUCCESS) {
        IAM_LOGI("service call return fail, ret:%{public}d", funcResult);
        return funcResult;
    }
    return SUCCESS;
}

int32_t UserAuthClientImpl::GetAvailableStatus(int32_t userId, AuthType authType, AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start, userId:%{public}d authType:%{public}d authTrustLevel:%{public}u",
        userId, authType, authTrustLevel);
    auto proxy = GetProxy();
    if (!proxy) {
        return LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_USER_AUTH_INTERNAL_PERMISSION
        }));
    }
    int32_t funcResult = SUCCESS;
    int32_t ret = proxy->GetAvailableStatus(INNER_API_VERSION_10000, userId, static_cast<int32_t>(authType),
        static_cast<uint32_t>(authTrustLevel), funcResult);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }
    if (funcResult != SUCCESS) {
        IAM_LOGI("service call return fail, ret:%{public}d", funcResult);
        return funcResult;
    }
    return SUCCESS;
}

void UserAuthClientImpl::GetProperty(int32_t userId, const GetPropertyRequest &request,
    const std::shared_ptr<GetPropCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d authType:%{public}d", userId, request.authType);
    if (!callback) {
        IAM_LOGE("get prop callback is nullptr");
        return;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_USER_AUTH_INTERNAL_PERMISSION
        }));
        callback->OnResult(result, extraInfo);
        return;
    }

    sptr<IGetExecutorPropertyCallback> wrapper(
        new (std::nothrow) GetExecutorPropertyCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    if (request.keys.empty() || request.keys.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("the attribute key vector is bad param, key size:%{public}zu", request.keys.size());
        Attributes attr;
        callback->OnResult(INVALID_PARAMETERS, attr);
        return;
    }

    std::vector<uint32_t> attrkeys;
    attrkeys.resize(request.keys.size());
    std::transform(request.keys.begin(), request.keys.end(), attrkeys.begin(), [](Attributes::AttributeKey key) {
        return static_cast<uint32_t>(key);
    });
    auto ret = proxy->GetProperty(userId, static_cast<int32_t>(request.authType), attrkeys, wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("GetProperty fail, ret:%{public}d", ret);
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
}

void UserAuthClientImpl::GetPropertyById(uint64_t credentialId, const std::vector<Attributes::AttributeKey> &keys,
    const std::shared_ptr<GetPropCallback> &callback)
{
    IAM_LOGD("start");
    if (!callback) {
        IAM_LOGE("get prop callback is nullptr");
        return;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_USER_AUTH_INTERNAL_PERMISSION
        }));
        callback->OnResult(result, extraInfo);
        return;
    }

    sptr<IGetExecutorPropertyCallback> wrapper(
        new (std::nothrow) GetExecutorPropertyCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    if (keys.empty() || keys.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("the attribute key vector is bad param, key size:%{public}zu", keys.size());
        Attributes attr;
        callback->OnResult(INVALID_PARAMETERS, attr);
        return;
    }
    std::vector<uint32_t> attrkeys;
    attrkeys.resize(keys.size());
    std::transform(keys.begin(), keys.end(), attrkeys.begin(), [](Attributes::AttributeKey key) {
        return static_cast<uint32_t>(key);
    });
    auto ret = proxy->GetPropertyById(credentialId, attrkeys, wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("GetPropertyById fail, ret:%{public}d", ret);
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
}

ResultCode UserAuthClientImpl::SetPropertyInner(int32_t userId, const SetPropertyRequest &request,
    const std::shared_ptr<SetPropCallback> &callback)
{
    auto proxy = GetProxy();
    if (!proxy) {
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_USER_AUTH_INTERNAL_PERMISSION
        }));
        return (ResultCode)result;
    }

    auto keys = request.attrs.GetKeys();
    IF_FALSE_LOGE_AND_RETURN_VAL(keys.size() == 1, GENERAL_ERROR);

    Attributes::AttributeKey key = keys[0];
    Attributes attr;

    std::vector<uint8_t> extraInfo;
    bool getArrayRet = request.attrs.GetUint8ArrayValue(static_cast<Attributes::AttributeKey>(key), extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getArrayRet, GENERAL_ERROR);

    bool setModeRet = attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, static_cast<uint32_t>(key));
    IF_FALSE_LOGE_AND_RETURN_VAL(setModeRet, GENERAL_ERROR);

    bool setArrayRet = attr.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(setArrayRet, GENERAL_ERROR);

    sptr<ISetExecutorPropertyCallback> wrapper(
        new (std::nothrow) SetExecutorPropertyCallbackService(callback));
    IF_FALSE_LOGE_AND_RETURN_VAL(wrapper != nullptr, GENERAL_ERROR);
    auto ret = proxy->SetProperty(userId, static_cast<int32_t>(request.authType), attr.Serialize(), wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("SetProperty fail, ret:%{public}d", ret);
        return (ResultCode)ret;
    }
    return SUCCESS;
}

void UserAuthClientImpl::SetProperty(int32_t userId, const SetPropertyRequest &request,
    const std::shared_ptr<SetPropCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d authType:%{public}d", userId, request.authType);
    if (!callback) {
        IAM_LOGE("set prop callback is nullptr");
        return;
    }

    ResultCode result = SetPropertyInner(userId, request, callback);
    if (result != SUCCESS) {
        IAM_LOGE("result is not success");
        Attributes retExtraInfo;
        callback->OnResult(GENERAL_ERROR, retExtraInfo);
        return;
    }
}

uint64_t UserAuthClientImpl::BeginAuthentication(const AuthParam &authParam,
    const std::shared_ptr<AuthenticationCallback> &callback)
{
    HILOG_COMM_INFO("begin auth, userId:%{public}d, authType:%{public}d, atl:%{public}u, authIntent:%{public}u,"
        " remoteAuthParamHasValue:%{public}s", authParam.userId, authParam.authType, authParam.authTrustLevel,
        authParam.authIntent, Common::GetBoolStr(authParam.remoteAuthParam.has_value()));
    if (authParam.remoteAuthParam.has_value()) {
        IAM_LOGI("verifierNetworkIdHasValue:%{public}s collectorNetworkIdHasValue:%{public}s "
            "collectorTokenIdHasValue:%{public}s",
            Common::GetBoolStr(authParam.remoteAuthParam->verifierNetworkId.has_value()),
            Common::GetBoolStr(authParam.remoteAuthParam->collectorNetworkId.has_value()),
            Common::GetBoolStr(authParam.remoteAuthParam->collectorTokenId.has_value()));
    }

    return BeginAuthenticationInner(authParam, callback);
}

uint64_t UserAuthClientImpl::BeginAuthenticationInner(const AuthParam &authParam,
    const std::shared_ptr<AuthenticationCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("auth callback is nullptr");
        return BAD_CONTEXT_ID;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_USER_AUTH_INTERNAL_PERMISSION
        }));
        callback->OnResult(result, extraInfo);
        return BAD_CONTEXT_ID;
    }

    sptr<IIamCallback> wrapper(new (std::nothrow) UserAuthCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    uint64_t contextId = BAD_CONTEXT_ID;
    IpcAuthParamInner ipcAuthParamInner = {
        .userId = authParam.userId,
        .challenge = authParam.challenge,
        .authType = static_cast<int32_t>(authParam.authType),
        .authTrustLevel = static_cast<int32_t>(authParam.authTrustLevel),
        .authIntent = static_cast<int32_t>(authParam.authIntent),
        .credentialIdList = std::vector<uint64_t>{},
    };
    IpcRemoteAuthParam ipcRemoteAuthParam = {};
    InitIpcRemoteAuthParam(authParam.remoteAuthParam, ipcRemoteAuthParam);
    auto ret = proxy->AuthUser(ipcAuthParamInner, ipcRemoteAuthParam, wrapper, contextId);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("auth user fail, ret:%{public}d, userId: %{public}d, authType: %{public}d,"
            " atl: %{public}u, authIntent: %{public}u, remoteAuthParamHasValue:%{public}s", ret,
            authParam.userId, authParam.authType, authParam.authTrustLevel, authParam.authIntent,
            Common::GetBoolStr(authParam.remoteAuthParam.has_value()));
        return BAD_CONTEXT_ID;
    }
    return contextId;
}

uint64_t UserAuthClientImpl::BeginNorthAuthentication(int32_t apiVersion, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel atl, const std::shared_ptr<AuthenticationCallback> &callback)
{
    HILOG_COMM_INFO("begin north auth, apiVersion:%{public}d authType:%{public}d atl:%{public}u",
        apiVersion, authType, atl);
    if (!callback) {
        IAM_LOGE("auth callback is nullptr");
        return BAD_CONTEXT_ID;
    }

    auto northCallback = Common::MakeShared<NorthAuthenticationCallback>(callback);
    if (!northCallback) {
        IAM_LOGE("auth callback is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_BIOMETRIC_PERMISSION
        }));
        callback->OnResult(result, extraInfo);
        return BAD_CONTEXT_ID;
    }

    sptr<IIamCallback> wrapper(new (std::nothrow) UserAuthCallbackService(northCallback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    uint64_t contextId = BAD_CONTEXT_ID;
    IpcAuthParamInner authParamInner = {
        .challenge = challenge,
        .authType = static_cast<int32_t>(authType),
        .authTrustLevel = static_cast<int32_t>(atl)
    };
    auto ret = proxy->Auth(apiVersion, authParamInner, wrapper, contextId);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("north auth fail, ret:%{public}d, authType:%{public}d atl:%{public}u,"
            " ctxId: %{public}s", ret, authType, atl, Common::GetMaskedString(contextId).c_str());
        return BAD_CONTEXT_ID;
    }
    return contextId;
}

int32_t UserAuthClientImpl::CancelAuthentication(uint64_t contextId)
{
    HILOG_COMM_INFO("cancel auth, contextId: %{public}hx", static_cast<uint16_t>(contextId));
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->CancelAuthOrIdentify(contextId, CancelReason::ORIGINAL_CANCEL);
}

uint64_t UserAuthClientImpl::BeginIdentification(const std::vector<uint8_t> &challenge, AuthType authType,
    const std::shared_ptr<IdentificationCallback> &callback)
{
    IAM_LOGI("start, authType:%{public}d", authType);
    if (!callback) {
        IAM_LOGE("identify callback is nullptr");
        return BAD_CONTEXT_ID;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_USER_AUTH_INTERNAL_PERMISSION
        }));
        callback->OnResult(result, extraInfo);
        return BAD_CONTEXT_ID;
    }

    sptr<IIamCallback> wrapper(new (std::nothrow) UserAuthCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    uint64_t contextId = BAD_CONTEXT_ID;
    auto ret = proxy->Identify(challenge, static_cast<int32_t>(authType), wrapper, contextId);
    if (ret != SUCCESS) {
        IAM_LOGE("Identify fail, ret:%{public}d", ret);
        return BAD_CONTEXT_ID;
    }
    return contextId;
}

int32_t UserAuthClientImpl::CancelIdentification(uint64_t contextId)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->CancelAuthOrIdentify(contextId, CancelReason::ORIGINAL_CANCEL);
}

int32_t UserAuthClientImpl::GetVersion(int32_t &version)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->GetVersion(version);
}

int32_t UserAuthClientImpl::SetGlobalConfigParam(const GlobalConfigParam &param)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }
    IpcGlobalConfigParam ipcGlobalConfigParam = {};
    InitIpcGlobalConfigParam(param, ipcGlobalConfigParam);
    return proxy->SetGlobalConfigParam(ipcGlobalConfigParam);
}

sptr<IUserAuth> UserAuthClientImpl::GetProxy()
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

void UserAuthClientImpl::ResetProxy(const wptr<IRemoteObject> &remote)
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

void UserAuthClientImpl::UserAuthImplDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    CallbackManager::GetInstance().OnServiceDeath();
    UserAuthClientImpl::Instance().ResetProxy(remote);
}

UserAuthClientImpl &UserAuthClientImpl::Instance()
{
    static UserAuthClientImpl impl;
    return impl;
}

UserAuthClient &UserAuthClient::GetInstance()
{
    return UserAuthClientImpl::Instance();
}

uint64_t UserAuthClientImpl::BeginWidgetAuth(const WidgetAuthParam &authParam, const WidgetParam &widgetParam,
    const std::shared_ptr<AuthenticationCallback> &callback)
{
    HILOG_COMM_INFO("begin widget auth, authTypeSize:%{public}zu authTrustLevel:%{public}u", authParam.authTypes.size(),
        authParam.authTrustLevel);
    AuthParamInner authParamInner = {
        .userId = authParam.userId,
        .isUserIdSpecified = true,
        .challenge = authParam.challenge,
        .authTypes = authParam.authTypes,
        .authTrustLevel = authParam.authTrustLevel,
        .reuseUnlockResult = authParam.reuseUnlockResult,
        .remoteTokenId = authParam.remoteTokenId,
    };
    WidgetParamInner widgetParamInner = {
        .title = widgetParam.title,
        .navigationButtonText = widgetParam.navigationButtonText,
        .windowMode = widgetParam.windowMode,
        .hasContext = false,
    };
    return BeginWidgetAuthInner(INNER_API_VERSION_20000, authParamInner, widgetParamInner, callback);
}

uint64_t UserAuthClientImpl::BeginWidgetAuth(int32_t apiVersion, const WidgetAuthParam &authParam,
    const WidgetParam &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback)
{
    HILOG_COMM_INFO("begin widget auth, apiVersion:%{public}d authTypeSize:%{public}zu authTrustLevel:%{public}u,"
        " reuseUnlockResult.isReuse: %{public}d, resuseMode: %{public}d", apiVersion,
        authParam.authTypes.size(), authParam.authTrustLevel, authParam.reuseUnlockResult.isReuse,
        authParam.reuseUnlockResult.reuseMode);

    AuthParamInner authParamInner = {
        .isUserIdSpecified = false,
        .challenge = authParam.challenge,
        .authTypes = authParam.authTypes,
        .authTrustLevel = authParam.authTrustLevel,
        .reuseUnlockResult = authParam.reuseUnlockResult,
        .remoteTokenId = authParam.remoteTokenId,
    };
    WidgetParamInner widgetParamInner = {
        .title = widgetParam.title,
        .navigationButtonText = widgetParam.navigationButtonText,
        .windowMode = widgetParam.windowMode,
        .hasContext = false,
    };
    return BeginWidgetAuthInner(apiVersion, authParamInner, widgetParamInner, callback);
}

uint64_t UserAuthClientImpl::BeginWidgetAuthInner(int32_t apiVersion, const AuthParamInner &authParam,
    const WidgetParamInner &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("auth callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_USER_AUTH_INTERNAL_PERMISSION,
            ACCESS_BIOMETRIC_PERMISSION
        }));
        callback->OnResult(result, extraInfo);
        return BAD_CONTEXT_ID;
    }

    sptr<IIamCallback> wrapper(new (std::nothrow) UserAuthCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
        return BAD_CONTEXT_ID;
    }

    // modal
    const std::shared_ptr<UserAuthModalInnerCallback> &modalCallback = Common::MakeShared<UserAuthModalInnerCallback>();
    sptr<IModalCallback> wrapperModal(new (std::nothrow) ModalCallbackService(modalCallback));
    if (wrapperModal == nullptr) {
        IAM_LOGE("failed to create wrapper for modal");
        Attributes extraInfo;
        callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
        return BAD_CONTEXT_ID;
    }
    IpcAuthParamInner ipcAuthParamInner = {};
    IpcWidgetParamInner ipcWidgetParamInner = {};
    InitIpcAuthParam(authParam, ipcAuthParamInner);
    InitIpcWidgetParam(widgetParam, ipcWidgetParamInner);
    uint64_t contextId = BAD_CONTEXT_ID;
    auto ret = proxy->AuthWidget(apiVersion, ipcAuthParamInner, ipcWidgetParamInner, wrapper, wrapperModal, contextId);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("auth widget fail, ret:%{public}d, authTypeSize: %{public}zu, authTrustLevel: %{public}u",
            ret, authParam.authTypes.size(), authParam.authTrustLevel);
        return BAD_CONTEXT_ID;
    }
    return contextId;
}

int32_t UserAuthClientImpl::SetWidgetCallback(int32_t version, const std::shared_ptr<IUserAuthWidgetCallback> &callback)
{
    IAM_LOGI("start, version:%{public}d", version);
    if (!callback) {
        IAM_LOGE("widget callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IWidgetCallback> wrapper(new (std::nothrow) WidgetCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }
    return proxy->RegisterWidgetCallback(version, wrapper);
}

int32_t UserAuthClientImpl::Notice(NoticeType noticeType, const std::string &eventData)
{
    IAM_LOGI("start, noticeType:%{public}d", noticeType);
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }
    HILOG_COMM_INFO("auth client notice noticeType:%{public}d, eventDat:%{public}s",
        static_cast<int32_t>(noticeType), eventData.c_str());
    return proxy->Notice(static_cast<int32_t>(noticeType), eventData);
}

int32_t UserAuthClientImpl::GetEnrolledState(int32_t apiVersion, AuthType authType, EnrolledState &enrolledState)
{
    IAM_LOGI("start, apiVersion:%{public}d authType:%{public}d ", apiVersion, authType);
    auto proxy = GetProxy();
    if (!proxy) {
        return LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_BIOMETRIC_PERMISSION
        }));
    }
    IpcEnrolledState ipcEnrolledState = {};
    int32_t funcResult = SUCCESS;
    int32_t ret = proxy->GetEnrolledState(apiVersion, static_cast<int32_t>(authType), ipcEnrolledState, funcResult);
    if (ret != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }
    if (funcResult != SUCCESS) {
        IAM_LOGI("service call return fail, ret:%{public}d", funcResult);
        return funcResult;
    }
    enrolledState.credentialCount = ipcEnrolledState.credentialCount;
    enrolledState.credentialDigest = ipcEnrolledState.credentialDigest;
    return SUCCESS;
}

void UserAuthClientImpl::GetAuthLockState(AuthType authType,
    const std::shared_ptr<GetPropCallback> &callback)
{
    IAM_LOGI("start, authType: %{public}d", authType);
    if (!callback) {
        IAM_LOGE("get prop callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            ACCESS_BIOMETRIC_PERMISSION
        }));
        callback->OnResult(result, extraInfo);
        return;
    }

    sptr<IGetExecutorPropertyCallback> wrapper(
        new (std::nothrow) GetExecutorPropertyCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    int32_t ret = proxy->GetAuthLockState(static_cast<int32_t>(authType), wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("GetAuthLockState fail, ret:%{public}d", ret);
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
}

int32_t UserAuthClientImpl::RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authTypes,
    const std::shared_ptr<AuthSuccessEventListener> &listener)
{
    IAM_LOGI("start");
    return EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().RegisterListener(authTypes, listener);
}

int32_t UserAuthClientImpl::UnRegistUserAuthSuccessEventListener(
    const std::shared_ptr<AuthSuccessEventListener> &listener)
{
    IAM_LOGI("start");
    return EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().UnRegisterListener(listener);
}

int32_t UserAuthClientImpl::PrepareRemoteAuth(const std::string &networkId,
    const std::shared_ptr<PrepareRemoteAuthCallback> &callback)
{
    IAM_LOGI("start");
    if (!callback) {
        IAM_LOGE("prepare remote auth callback is nullptr");
        return GENERAL_ERROR;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        callback->OnResult(GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    sptr<IIamCallback> wrapper(new (std::nothrow) UserAuthCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        callback->OnResult(GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    return proxy->PrepareRemoteAuth(networkId, wrapper);
}

int32_t UserAuthClientImpl::QueryReusableAuthResult(const WidgetAuthParam &authParam, std::vector<uint8_t> &token)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = authParam.userId;
    ipcAuthParamInner.isUserIdSpecified = (authParam.userId != INVALID_USER_ID);
    ipcAuthParamInner.challenge = authParam.challenge;
    for (auto &authType : authParam.authTypes) {
        ipcAuthParamInner.authTypes.push_back(static_cast<int32_t>(authType));
    }
    ipcAuthParamInner.authTrustLevel = authParam.authTrustLevel,
    ipcAuthParamInner.reuseUnlockResult.isReuse = authParam.reuseUnlockResult.isReuse;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = authParam.reuseUnlockResult.reuseMode;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = authParam.reuseUnlockResult.reuseDuration;

    auto ret = proxy->QueryReusableAuthResult(ipcAuthParamInner, token);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("query reuseable auth result: %{public}d, atl: %{public}d, isReuse: %{public}d,"
            " reuseMode: %{public}d", ret, authParam.authTrustLevel, authParam.reuseUnlockResult.isReuse,
            authParam.reuseUnlockResult.reuseMode);
    }

    return ret;
}

int32_t UserAuthClientImpl::RegisterRemoteAuthCallback(
    const std::shared_ptr<RemoteAuthClientCallback> &remoteAuthCallback)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IRemoteAuthCallback> wrapper(new (std::nothrow) RemoteAuthCallbackService(remoteAuthCallback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }

    return proxy->RegisterRemoteAuthCallback(wrapper);
}

int32_t UserAuthClientImpl::UnregisterRemoteAuthCallback()
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->UnregisterRemoteAuthCallback();
}

void UserAuthClientImpl::InitIpcRemoteAuthParam(const std::optional<RemoteAuthParam> &remoteAuthParam,
    IpcRemoteAuthParam &ipcRemoteAuthParam)
{
    ipcRemoteAuthParam.isHasRemoteAuthParam = false;
    ipcRemoteAuthParam.isHasVerifierNetworkId = false;
    ipcRemoteAuthParam.isHasCollectorNetworkId = false;
    ipcRemoteAuthParam.isHasCollectorTokenId = false;
    if (remoteAuthParam.has_value()) {
        ipcRemoteAuthParam.isHasRemoteAuthParam = true;
        if (remoteAuthParam.value().verifierNetworkId.has_value()) {
            ipcRemoteAuthParam.isHasVerifierNetworkId = true;
            ipcRemoteAuthParam.verifierNetworkId = remoteAuthParam.value().verifierNetworkId.value();
        }
        if (remoteAuthParam.value().collectorNetworkId.has_value()) {
            ipcRemoteAuthParam.isHasCollectorNetworkId = true;
            ipcRemoteAuthParam.collectorNetworkId = remoteAuthParam.value().collectorNetworkId.value();
        }
        if (remoteAuthParam.value().collectorTokenId.has_value()) {
            ipcRemoteAuthParam.isHasCollectorTokenId = true;
            ipcRemoteAuthParam.collectorTokenId = remoteAuthParam.value().collectorTokenId.value();
        }
    }
}

void UserAuthClientImpl::InitIpcGlobalConfigParam(const GlobalConfigParam &globalConfigParam,
    IpcGlobalConfigParam &ipcGlobalConfigParam)
{
    ipcGlobalConfigParam.type = static_cast<int32_t>(globalConfigParam.type);
    if (globalConfigParam.type == PIN_EXPIRED_PERIOD) {
        ipcGlobalConfigParam.value.pinExpiredPeriod = globalConfigParam.value.pinExpiredPeriod;
    } else if (globalConfigParam.type == ENABLE_STATUS) {
        ipcGlobalConfigParam.value.enableStatus = globalConfigParam.value.enableStatus;
    } else if (globalConfigParam.type == PIN_ALGO_TYPE) {
        ipcGlobalConfigParam.value.pinAlgoType = globalConfigParam.value.pinAlgoType;
    }
    ipcGlobalConfigParam.userIds = globalConfigParam.userIds;
    ipcGlobalConfigParam.authTypes.resize(globalConfigParam.authTypes.size());
    std::transform(globalConfigParam.authTypes.begin(), globalConfigParam.authTypes.end(),
        ipcGlobalConfigParam.authTypes.begin(), [](AuthType authType) {
        return static_cast<int32_t>(authType);
    });
}

void UserAuthClientImpl::InitIpcAuthParam(const AuthParamInner &authParam,
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
    ipcAuthParamInner.authTrustLevel = static_cast<uint32_t>(authParam.authTrustLevel);
    ipcAuthParamInner.authIntent = static_cast<int32_t>(authParam.authIntent);
    ipcAuthParamInner.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    ipcAuthParamInner.credentialIdList = authParam.credentialIdList;
    ipcAuthParamInner.reuseUnlockResult.isReuse = authParam.reuseUnlockResult.isReuse;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = authParam.reuseUnlockResult.reuseMode;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = authParam.reuseUnlockResult.reuseDuration;
    if (authParam.remoteTokenId.has_value()) {
        ipcAuthParamInner.isHasRemoteTokenId = true;
        ipcAuthParamInner.remoteTokenId = authParam.remoteTokenId.value();
    }
}

void UserAuthClientImpl::InitIpcWidgetParam(const WidgetParamInner &widgetParam,
    IpcWidgetParamInner &ipcWidgetParamInner)
{
    ipcWidgetParamInner.title = widgetParam.title;
    ipcWidgetParamInner.navigationButtonText = widgetParam.navigationButtonText;
    ipcWidgetParamInner.windowMode = static_cast<int32_t>(widgetParam.windowMode);
    ipcWidgetParamInner.hasContext = widgetParam.hasContext;
}

void UserAuthClientImpl::CleanUpResource()
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN(proxy_ != nullptr);
    ResetProxy(proxy_->AsObject());
}

UserAuthClientImpl::~UserAuthClientImpl()
{
    IAM_LOGI("start");
    CleanUpResource();
}

extern "C" __attribute__((destructor)) void CleanUp()
{
    UserAuthClientImpl::Instance().CleanUpResource();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

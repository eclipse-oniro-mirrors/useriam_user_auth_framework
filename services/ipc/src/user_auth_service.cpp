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

#include "user_auth_service.h"
#include "hisysevent_adapter.h"

#include <algorithm>
#include <cinttypes>

#include "accesstoken_kit.h"
#include "auth_common.h"
#include "event_listener_manager.h"
#include "auth_widget_helper.h"
#include "context_factory.h"
#include "context_helper.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "iam_time.h"
#include "ipc_common.h"
#include "ipc_skeleton.h"
#include "service_init_manager.h"
#include "widget_client.h"
#include "auth_widget_helper.h"
#include "remote_msg_util.h"
#include "remote_iam_callback.h"
#include "remote_auth_service.h"
#include "remote_auth_callback_manager.h"
#include "thread_handler_manager.h"
#include "user_auth_helper.h"
#include "device_manager_util.h"
#include "xcollie_helper.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
#ifndef IAM_TEST_ENABLE
namespace {
#endif
const int32_t MINIMUM_VERSION = 0;
const int32_t CURRENT_VERSION = 1;
const int32_t USERIAM_IPC_THREAD_NUM = 4;
const uint32_t NETWORK_ID_LENGTH = 64;
int32_t GetTemplatesByAuthType(int32_t userId, AuthType authType, std::vector<uint64_t> &templateIds)
{
    templateIds.clear();
    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType, credentialInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
            userId, authType);
        return GENERAL_ERROR;
    }

    if (credentialInfos.empty()) {
        IAM_LOGE("user %{public}d has no credential type %{public}d", userId, authType);
        return SUCCESS;
    }

    templateIds.reserve(credentialInfos.size());
    for (auto &info : credentialInfos) {
        if (info == nullptr) {
            IAM_LOGE("info is nullptr");
            continue;
        }
        templateIds.push_back(info->GetTemplateId());
    }

    return SUCCESS;
}

bool IsTemplateIdListRequired(const std::vector<Attributes::AttributeKey> &keys)
{
    for (const auto &key : keys) {
        if (key == Attributes::AttributeKey::ATTR_PIN_SUB_TYPE ||
            key == Attributes::AttributeKey::ATTR_REMAIN_TIMES ||
            key == Attributes::AttributeKey::ATTR_FREEZING_TIME ||
            key == Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION ||
            key == Attributes::AttributeKey::ATTR_CREDENTIAL_LENGTH) {
            return true;
        }
    }
    return false;
}

void GetResourceNodeByTypeAndRole(AuthType authType, ExecutorRole role,
    std::vector<std::weak_ptr<ResourceNode>> &authTypeNodes)
{
    authTypeNodes.clear();
    ResourceNodePool::Instance().Enumerate(
        [&authTypeNodes, role, authType](const std::weak_ptr<ResourceNode> &weakNode) {
            auto node = weakNode.lock();
            if (node == nullptr) {
                return;
            }
            if (node->GetAuthType() != authType) {
                return;
            }
            if (node->GetExecutorRole() != role) {
                return;
            }
            authTypeNodes.push_back(node);
        });
}

std::string GetAuthParamStr(const AuthParamInner &authParam, std::optional<RemoteAuthParam> &remoteAuthParam)
{
    std::ostringstream authParamString;
    authParamString << "userId:" << authParam.userId << " authType:" << authParam.authType
                    << " authIntent:" << authParam.authIntent << " atl:" << authParam.authTrustLevel;
    if (remoteAuthParam.has_value()) {
        const uint32_t networkIdPrintLen = 4;
        const uint32_t tokenIdMinLen = 2;
        auto verifierNetworkIdStr = remoteAuthParam->verifierNetworkId.value_or("").substr(0, networkIdPrintLen);
        auto collectorNetworkIdStr = remoteAuthParam->collectorNetworkId.value_or("").substr(0, networkIdPrintLen);
        auto tokenIdStr = std::to_string(remoteAuthParam->collectorTokenId.value_or(0));
        if (tokenIdStr.size() > tokenIdMinLen) {
            tokenIdStr = std::string(1, tokenIdStr[0]) + "****" + std::string(1, tokenIdStr[tokenIdStr.size() - 1]);
        } else {
            tokenIdStr = "";
        }

        authParamString << " isRemoteAuth:true" << " verifierNetworkId:" << verifierNetworkIdStr << "****"
            " collectorNetworkId:" << collectorNetworkIdStr << "****" << " collectorTokenId:" << tokenIdStr;
    }
    return authParamString.str();
}
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(UserAuthService::GetInstance().get());
#ifndef IAM_TEST_ENABLE
} // namespace
#endif
std::mutex UserAuthService::mutex_;
std::shared_ptr<UserAuthService> UserAuthService::instance_ = nullptr;

std::shared_ptr<UserAuthService> UserAuthService::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (instance_ == nullptr) {
            instance_ = Common::MakeShared<UserAuthService>();
            if (instance_ == nullptr) {
                IAM_LOGE("make share failed");
            }
        }
    }
    return instance_;
}

UserAuthService::UserAuthService()
    : SystemAbility(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH, true), UserAuthStub(false)
{}

void UserAuthService::OnStart()
{
    IAM_LOGI("Sa start UserAuthService");
    IPCSkeleton::SetMaxWorkThreadNum(USERIAM_IPC_THREAD_NUM);
    if (!Publish(this)) {
        IAM_LOGE("failed to publish service");
    }
    ServiceInitManager::GetInstance().OnUserAuthServiceStart();
}

void UserAuthService::OnStop()
{
    IAM_LOGI("Sa stop UserAuthService");
    ServiceInitManager::GetInstance().OnUserAuthServiceStop();
}

bool UserAuthService::CheckAuthTrustLevel(AuthTrustLevel authTrustLevel, int32_t authType)
{
    if (authType == AuthType::COMPANION_DEVICE) {
        IAM_LOGI("authType is %{public}d, omit atl check", authType);
        return true;
    }
    if ((authTrustLevel != ATL1) && (authTrustLevel != ATL2) &&
        (authTrustLevel != ATL3) && (authTrustLevel != ATL4)) {
        IAM_LOGE("authTrustLevel not support %{public}u", authTrustLevel);
        return false;
    }
    return true;
}

int32_t UserAuthService::GetAvailableStatus(int32_t apiVersion, int32_t userId, int32_t authType,
    uint32_t authTrustLevel, int32_t &funcResult)
{
    IAM_LOGD("start");
    funcResult = GetAvailableStatusImpl(apiVersion, userId, authType, authTrustLevel);
    return SUCCESS;
}

int32_t UserAuthService::GetAvailableStatus(int32_t apiVersion, int32_t authType, uint32_t authTrustLevel,
    int32_t &funcResult)
{
    IAM_LOGD("start");
    funcResult = GetAvailableStatusImpl(apiVersion, authType, authTrustLevel);
    return SUCCESS;
}

int32_t UserAuthService::GetAvailableStatusImpl(int32_t apiVersion, int32_t userId, int32_t authType,
    uint32_t authTrustLevel)
{
    IAM_LOGD("start with userId");

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    return GetAvailableStatusInner(apiVersion, userId, static_cast<AuthType>(authType),
        static_cast<AuthTrustLevel>(authTrustLevel));
}

int32_t UserAuthService::GetAvailableStatusImpl(int32_t apiVersion, int32_t authType, uint32_t authTrustLevel)
{
    IAM_LOGD("start without userId");
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (apiVersion <= API_VERSION_8 && static_cast<AuthType>(authType) == PIN) {
        IAM_LOGE("authType not support");
        return TYPE_NOT_SUPPORT;
    }
    int32_t userId = INVALID_USER_ID;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        return GENERAL_ERROR;
    }
    return GetAvailableStatusInner(apiVersion, userId, static_cast<AuthType>(authType),
        static_cast<AuthTrustLevel>(authTrustLevel));
}

int32_t UserAuthService::GetAvailableStatusInner(int32_t apiVersion, int32_t userId, AuthType authType,
    AuthTrustLevel authTrustLevel)
{
    if (!CheckAuthTrustLevel(authTrustLevel, authType)) {
        IAM_LOGE("authTrustLevel is not in correct range");
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return GENERAL_ERROR;
    }
    int32_t checkRet = GENERAL_ERROR;
    int32_t result = hdi->GetAvailableStatus(userId, authType, authTrustLevel, checkRet);
    if (result != SUCCESS) {
        IAM_LOGE("hdi GetAvailableStatus failed");
        return GENERAL_ERROR;
    }
    IAM_LOGI("GetAvailableStatus result:%{public}d", checkRet);
    return checkRet;
}

void UserAuthService::FillGetPropertyKeys(AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
    std::vector<uint32_t> &uint32Keys)
{
    uint32Keys.reserve(keys.size());
    for (const auto &key : keys) {
        if (key == Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION && authType != PIN) {
            continue;
        }
        uint32Keys.push_back(static_cast<uint32_t>(key));
    }
}

void UserAuthService::FillGetPropertyValue(AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
    Attributes &values)
{
    for (const auto &key : keys) {
        if (key == Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION && authType != PIN) {
            if (!values.SetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, FIRST_LOCKOUT_DURATION_EXCEPT_PIN)) {
                IAM_LOGE("set nextFailLockoutDuration failed, authType %{public}d", authType);
            }
            break;
        }
    }
}

std::shared_ptr<ResourceNode> UserAuthService::GetResourseNode(AuthType authType)
{
    std::vector<std::weak_ptr<ResourceNode>> authTypeNodes;
    GetResourceNodeByTypeAndRole(authType, ALL_IN_ONE, authTypeNodes);
    if (authTypeNodes.size() != 1) {
        IAM_LOGE("auth type %{public}d resource node num %{public}zu is not expected",
            authType, authTypeNodes.size());
        return nullptr;
    }

    auto resourceNode = authTypeNodes[0].lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        return nullptr;
    }

    return resourceNode;
}

int32_t UserAuthService::GetPropertyInner(AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
    const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback, std::vector<uint64_t> &templateIds)
{
    Attributes values;
    auto resourceNode = GetResourseNode(authType);
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        getExecutorPropertyCallback->OnGetExecutorPropertyResult(GENERAL_ERROR, values.Serialize());
        return SUCCESS;
    }

    std::vector<uint32_t> uint32Keys;
    FillGetPropertyKeys(authType, keys, uint32Keys);
    Attributes attr;
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIds);
    attr.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, uint32Keys);

    int32_t result = resourceNode->GetProperty(attr, values);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get property, result = %{public}d", result);
    }
    FillGetPropertyValue(authType, keys, values);

    getExecutorPropertyCallback->OnGetExecutorPropertyResult(result, values.Serialize());
    return SUCCESS;
}

int32_t UserAuthService::GetProperty(int32_t userId, int32_t authType,
    const std::vector<uint32_t> &keys, const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback)
{
    IAM_LOGD("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExecutorPropertyCallback != nullptr, INVALID_PARAMETERS);
    Attributes values;

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        getExecutorPropertyCallback->OnGetExecutorPropertyResult(CHECK_PERMISSION_FAILED, values.Serialize());
        return SUCCESS;
    }

    ThreadHandlerManager::GetInstance().PostTaskOnTemporaryThread("GetProperty", [this, userId, authType,
        keys, getExecutorPropertyCallback]() {
            std::vector<Attributes::AttributeKey> attrKeys;
            attrKeys.resize(keys.size());
            std::transform(keys.begin(), keys.end(), attrKeys.begin(), [](uint32_t key) {
                return static_cast<Attributes::AttributeKey>(key);
            });

            (void)GetPropertyHelper(userId, AuthType(authType), attrKeys, getExecutorPropertyCallback);
    });
    return SUCCESS;
}

int32_t UserAuthService::GetPropertyHelper(int32_t userId, int32_t authType,
    const std::vector<Attributes::AttributeKey> &keys,
    const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback)
{
    IAM_LOGD("start");
    Attributes values;
    std::vector<uint64_t> templateIds;
    if (IsTemplateIdListRequired(keys)) {
        int32_t ret = GetTemplatesByAuthType(userId, static_cast<AuthType>(authType), templateIds);
        if (ret != SUCCESS) {
            IAM_LOGE("get templates fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
                userId, authType);
            getExecutorPropertyCallback->OnGetExecutorPropertyResult(GENERAL_ERROR, values.Serialize());
            return SUCCESS;
        }
        if (templateIds.size() == 0) {
            IAM_LOGE("template id list is required, but templateIds size is 0");
            getExecutorPropertyCallback->OnGetExecutorPropertyResult(NOT_ENROLLED, values.Serialize());
            return SUCCESS;
        }
    }

    return GetPropertyInner(static_cast<AuthType>(authType), keys, getExecutorPropertyCallback, templateIds);
}

int32_t UserAuthService::GetPropertyById(uint64_t credentialId, const std::vector<uint32_t> &keys,
    const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback)
{
    IAM_LOGD("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExecutorPropertyCallback != nullptr, INVALID_PARAMETERS);
    Attributes values;

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        getExecutorPropertyCallback->OnGetExecutorPropertyResult(CHECK_PERMISSION_FAILED, values.Serialize());
        return SUCCESS;
    }

    ThreadHandlerManager::GetInstance().PostTaskOnTemporaryThread("GetPropertyById",
        [this, credentialId, keys, getExecutorPropertyCallback]() {
            std::shared_ptr<CredentialInfoInterface> credInfo;
            std::vector<uint64_t> templateIds;
            Attributes attrValues;
            int32_t ret = UserIdmDatabase::Instance().GetCredentialInfoById(credentialId, credInfo);
            if (ret != SUCCESS) {
                IAM_LOGE("get credentialInfp fail, ret:%{public}d", ret);
                getExecutorPropertyCallback->OnGetExecutorPropertyResult(ret, attrValues.Serialize());
                return;
            }
            if (credInfo == nullptr) {
                IAM_LOGE("credential is nullptr");
                getExecutorPropertyCallback->OnGetExecutorPropertyResult(GENERAL_ERROR, attrValues.Serialize());
                return;
            }

            std::vector<Attributes::AttributeKey> attrKeys;
            attrKeys.resize(keys.size());
            std::transform(keys.begin(), keys.end(), attrKeys.begin(), [](uint32_t key) {
                return static_cast<Attributes::AttributeKey>(key);
            });
            AuthType authType = credInfo->GetAuthType();
            templateIds.push_back(credInfo->GetTemplateId());
            (void)GetPropertyInner(authType, attrKeys, getExecutorPropertyCallback, templateIds);
    });

    return SUCCESS;
}

int32_t UserAuthService::SetProperty(int32_t userId, int32_t authType, const std::vector<uint8_t> &attributes,
    const sptr<ISetExecutorPropertyCallback> &setExecutorPropertyCallback)
{
    IAM_LOGD("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (setExecutorPropertyCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("permission check failed");
        setExecutorPropertyCallback->OnSetExecutorPropertyResult(CHECK_PERMISSION_FAILED);
        return CHECK_PERMISSION_FAILED;
    }

    ThreadHandlerManager::GetInstance().PostTaskOnTemporaryThread("setProperty", [this, userId, authType,
        attributes, setExecutorPropertyCallback]() {
            std::vector<std::weak_ptr<ResourceNode>> authTypeNodes;
            GetResourceNodeByTypeAndRole(static_cast<AuthType>(authType), ALL_IN_ONE, authTypeNodes);
            if (authTypeNodes.size() != 1) {
                IAM_LOGE("auth type %{public}d resource node num %{public}zu is not expected",
                    authType, authTypeNodes.size());
                setExecutorPropertyCallback->OnSetExecutorPropertyResult(GENERAL_ERROR);
                return;
            }

            auto resourceNode = authTypeNodes[0].lock();
            if (resourceNode == nullptr) {
                IAM_LOGE("resourceNode is nullptr");
                setExecutorPropertyCallback->OnSetExecutorPropertyResult(GENERAL_ERROR);
                return;
            }
            const Attributes properties(attributes);
            int32_t result = resourceNode->SetProperty(properties);
            if (result != SUCCESS) {
                IAM_LOGE("set property failed, result = %{public}d", result);
            }
            setExecutorPropertyCallback->OnSetExecutorPropertyResult(result);
    });

    return SUCCESS;
}

std::shared_ptr<ContextCallback> UserAuthService::GetAuthContextCallback(int32_t apiVersion,
    const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const sptr<IIamCallback> &userAuthCallback)
{
    if (userAuthCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return nullptr;
    }
    auto contextCallback = ContextCallback::NewInstance(userAuthCallback, TRACE_AUTH_USER_ALL);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        Attributes extraInfo;
        userAuthCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return nullptr;
    }
    contextCallback->SetTraceAuthType(authType);
    contextCallback->SetTraceAuthWidgetType(authType);
    contextCallback->SetTraceAuthTrustLevel(authTrustLevel);
    contextCallback->SetTraceSdkVersion(apiVersion);
    return contextCallback;
}

int32_t UserAuthService::CheckAuthPermissionAndParam(int32_t authType, const int32_t &callerType,
    const std::string &callerName, AuthTrustLevel authTrustLevel)
{
    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (callerType == Security::AccessToken::TOKEN_HAP && (!IpcCommon::CheckForegroundApplication(callerName))) {
        IAM_LOGE("failed to check foreground application");
        return CHECK_PERMISSION_FAILED;
    }
    if (authType == PIN) {
        IAM_LOGE("authType not support");
        return TYPE_NOT_SUPPORT;
    }
    if (!CheckAuthTrustLevel(authTrustLevel, authType)) {
        IAM_LOGE("authTrustLevel is not in correct range");
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    return SUCCESS;
}

int32_t UserAuthService::StartAuth(int32_t apiVersion, Authentication::AuthenticationPara &para,
    std::shared_ptr<ContextCallback> &contextCallback, uint64_t &contextId)
{
    IAM_LOGI("start");
    contextId = StartAuthContext(apiVersion, para, contextCallback, true);
    if (contextId == BAD_CONTEXT_ID) {
        IAM_LOGE("StartAuthContext fail");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthService::Auth(int32_t apiVersion, const IpcAuthParamInner &ipcAuthParamInner,
    const sptr<IIamCallback> &userAuthCallback, uint64_t &contextId)
{
    IAM_LOGI("start");
    auto contextCallback = GetAuthContextCallback(apiVersion, ipcAuthParamInner.challenge,
        static_cast<AuthType>(ipcAuthParamInner.authType),
        static_cast<AuthTrustLevel>(ipcAuthParamInner.authTrustLevel), userAuthCallback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    Attributes extraInfo;
    Authentication::AuthenticationPara para = {};
    if ((!IpcCommon::GetCallerName(*this, para.callerName, para.callerType))) {
        IAM_LOGE("get bundle name fail");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Auth GetCallerName fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    contextCallback->SetTraceCallerName(para.callerName);
    contextCallback->SetTraceCallerType(para.callerType);
    int32_t checkRet = CheckAuthPermissionAndParam(static_cast<AuthType>(ipcAuthParamInner.authType), para.callerType,
        para.callerName, static_cast<AuthTrustLevel>(ipcAuthParamInner.authTrustLevel));
    if (checkRet != SUCCESS) {
        IAM_LOGE("check auth permission and param fail");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Auth CheckAuthPermissionAndParam fail");
        contextCallback->OnResult(checkRet, extraInfo);
        return checkRet;
    }
    int32_t userId = INVALID_USER_ID;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("get callingUserId failed");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Auth GetCallingUserId fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }
    contextCallback->SetTraceUserId(userId);
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.userId = userId;
    para.authType = static_cast<AuthType>(ipcAuthParamInner.authType);
    para.atl = static_cast<AuthTrustLevel>(ipcAuthParamInner.authTrustLevel);
    para.challenge = std::move(ipcAuthParamInner.challenge);
    para.endAfterFirstFail = true;
    para.sdkVersion = apiVersion;
    para.authIntent = AuthIntent::DEFAULT;
    para.isOsAccountVerified = IpcCommon::IsOsAccountVerified(userId);
    return StartAuth(apiVersion, para, contextCallback, contextId);
}

uint64_t UserAuthService::StartAuthContext(int32_t apiVersion, Authentication::AuthenticationPara para,
    const std::shared_ptr<ContextCallback> &contextCallback, bool needSubscribeAppState)
{
    HILOG_COMM_INFO("auth service start context: useId: %{public}d, authType: %{public}d,"
        " atl: %{public}d, callerName: %{public}s, authIntent: %{public}d, isOsAccountVerified: %{public}d",
        para.userId, para.authType, para.atl, para.callerName.c_str(), para.authIntent, para.isOsAccountVerified);
    Attributes extraInfo;
    auto context = ContextFactory::CreateSimpleAuthContext(para, contextCallback, needSubscribeAppState);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Auth insert context fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    contextCallback->SetTraceAuthContextId(context->GetContextId());
    contextCallback->SetCleaner(ContextHelper::Cleaner(context));

    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(handler != nullptr, BAD_CONTEXT_ID);
    std::weak_ptr<Context> weakContext = context;
    std::weak_ptr<ContextCallback> weakContextCallback = contextCallback;
    handler->PostTask([weakContext, weakContextCallback, apiVersion]() {
        auto sharedContext = weakContext.lock();
        IF_FALSE_LOGE_AND_RETURN(sharedContext != nullptr);
        auto sharedContextCallback = weakContextCallback.lock();
        IF_FALSE_LOGE_AND_RETURN(sharedContextCallback != nullptr);
        if (!sharedContext->Start()) {
            int32_t errorCode = sharedContext->GetLatestError();
            IAM_LOGE("failed to start auth apiVersion:%{public}d errorCode:%{public}d", apiVersion, errorCode);
            sharedContextCallback->SetTraceAuthFinishReason("UserAuthService Auth start context fail");
            Attributes tmpExtraInfo;
            sharedContextCallback->OnResult(errorCode, tmpExtraInfo);
            return;
        }
    });

    return context->GetContextId();
}

uint64_t UserAuthService::StartRemoteAuthInvokerContext(AuthParamInner authParam,
    RemoteAuthInvokerContextParam &param, const std::shared_ptr<ContextCallback> &contextCallback)
{
    Attributes extraInfo;
    std::shared_ptr<Context> context = ContextFactory::CreateRemoteAuthInvokerContext(authParam, param,
        contextCallback);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->SetTraceAuthFinishReason("UserAuthService StartRemoteAuthInvokerContext insert context fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetCleaner(ContextHelper::Cleaner(context));
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    contextCallback->SetTraceAuthContextId(context->GetContextId());

    if (!context->Start()) {
        int32_t errorCode = context->GetLatestError();
        IAM_LOGE("failed to start auth errorCode:%{public}d", errorCode);
        contextCallback->SetTraceAuthFinishReason("UserAuthService StartRemoteAuthInvokerContext start context fail");
        contextCallback->OnResult(errorCode, extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

uint64_t UserAuthService::StartLocalRemoteAuthContext(Authentication::AuthenticationPara para,
    LocalRemoteAuthContextParam &localRemoteAuthContextParam, const std::shared_ptr<ContextCallback> &contextCallback)
{
    Attributes extraInfo;
    std::shared_ptr<Context> context = ContextFactory::CreateLocalRemoteAuthContext(para, localRemoteAuthContextParam,
        contextCallback);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->SetTraceAuthFinishReason("UserAuthService StartLocalRemoteAuthContext insert context fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetCleaner(ContextHelper::Cleaner(context));
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    contextCallback->SetTraceAuthContextId(context->GetContextId());

    if (!context->Start()) {
        int32_t errorCode = context->GetLatestError();
        IAM_LOGE("failed to start auth errorCode:%{public}d", errorCode);
        contextCallback->SetTraceAuthFinishReason("UserAuthService StartLocalRemoteAuthContext start context fail");
        contextCallback->OnResult(errorCode, extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

bool UserAuthService::CheckAuthPermissionAndParam(AuthType authType, AuthTrustLevel authTrustLevel,
    const std::shared_ptr<ContextCallback> &contextCallback, Attributes &extraInfo)
{
    if (!CheckAuthTrustLevel(authTrustLevel, authType)) {
        IAM_LOGE("authTrustLevel is not in correct range");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthUser CheckAuthTrustLevel fail");
        contextCallback->OnResult(TRUST_LEVEL_NOT_SUPPORT, extraInfo);
        return false;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthUser CheckPermission fail");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return false;
    }
    return true;
}

int32_t UserAuthService::StartAuthUser(AuthParamInner &authParam, std::optional<RemoteAuthParam> &remoteAuthParam,
    Authentication::AuthenticationPara &para, std::shared_ptr<ContextCallback> &contextCallback, uint64_t &contextId)
{
    Attributes extraInfo;
    if (!remoteAuthParam.has_value()) {
        bool needSubscribeAppState = !IpcCommon::CheckPermission(*this, USER_AUTH_FROM_BACKGROUND);
        contextId = StartAuthContext(INNER_API_VERSION_10000, para, contextCallback, needSubscribeAppState);
        if (contextId == BAD_CONTEXT_ID) {
            IAM_LOGE("StartAuthContext fail");
            return GENERAL_ERROR;
        }
        return SUCCESS;
    }

    ResultCode failReason = GENERAL_ERROR;
    contextId = AuthRemoteUser(authParam, para, remoteAuthParam.value(), contextCallback, failReason);
    if (contextId == BAD_CONTEXT_ID) {
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthRemoteUser fail");
        contextCallback->OnResult(failReason, extraInfo);
        return failReason;
    }

    IAM_LOGI("success");
    return SUCCESS;
}

int32_t UserAuthService::AuthUser(const IpcAuthParamInner &ipcAuthParamInner,
    const IpcRemoteAuthParam &ipcRemoteAuthParam, const sptr<IIamCallback> &userAuthCallback,
    uint64_t &contextId)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    contextId = BAD_CONTEXT_ID;
    AuthParamInner authParam = {};
    std::optional<RemoteAuthParam> remoteAuthParam = std::nullopt;
    InitAuthParam(ipcAuthParamInner, authParam);
    InitRemoteAuthParam(ipcRemoteAuthParam, remoteAuthParam);
    IAM_LOGI("start, %{public}s", GetAuthParamStr(authParam, remoteAuthParam).c_str());
    auto contextCallback = GetAuthContextCallback(INNER_API_VERSION_10000, authParam.challenge, authParam.authType,
        authParam.authTrustLevel, userAuthCallback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return GENERAL_ERROR;
    }
    contextCallback->SetTraceIsRemoteAuth(remoteAuthParam.has_value());
    contextCallback->SetTraceUserId(authParam.userId);
    Attributes extraInfo;
    Authentication::AuthenticationPara para = {};
    if ((!IpcCommon::GetCallerName(*this, para.callerName, para.callerType))) {
        IAM_LOGE("get caller name fail");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthUser GetCallerName fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    contextCallback->SetTraceCallerName(para.callerName);
    contextCallback->SetTraceCallerType(para.callerType);
    if (CheckAuthPermissionAndParam(authParam.authType, authParam.authTrustLevel, contextCallback,
        extraInfo) == false) {
        return CHECK_PERMISSION_FAILED;
    }
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.userId = authParam.userId;
    para.authType = authParam.authType;
    para.atl = authParam.authTrustLevel;
    para.challenge = authParam.challenge;
    para.endAfterFirstFail = false;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.authIntent = authParam.authIntent;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.credentialIdList = authParam.credentialIdList;
    para.isOsAccountVerified = IpcCommon::IsOsAccountVerified(authParam.userId);
    return StartAuthUser(authParam, remoteAuthParam, para, contextCallback, contextId);
}

int32_t UserAuthService::DoPrepareRemoteAuth(const std::string &networkId)
{
    IAM_LOGI("start");

    std::string udid;
    bool getUdidRet = DeviceManagerUtil::GetInstance().GetUdidByNetworkId(networkId, udid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getUdidRet, GENERAL_ERROR);

    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, GENERAL_ERROR);

    int32_t hdiRet = hdi->PrepareRemoteAuth(udid);
    if (hdiRet == DEVICE_CAPABILITY_NOT_SUPPORT || hdiRet == REMOTE_DEVICE_CONNECTION_FAIL) {
        IAM_LOGE("prepare remote auth failed, ret: %{public}d", hdiRet);
        return hdiRet;
    }
    IF_FALSE_LOGE_AND_RETURN_VAL(hdiRet == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

int32_t UserAuthService::PrepareRemoteAuthInner(const std::string &networkId,
    const sptr<IIamCallback> &callback)
{
    if (networkId.empty()) {
        IAM_LOGE("networkId is empty");
        return INVALID_PARAMETERS;
    }

    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(handler != nullptr, GENERAL_ERROR);

    handler->PostTask([networkId, callback]() {
        Attributes attr;

        auto service = UserAuthService::GetInstance();
        if (service == nullptr) {
            IAM_LOGE("service is nullptr");
            callback->OnResult(GENERAL_ERROR, attr.Serialize());
            return;
        }

        int32_t ret = service->DoPrepareRemoteAuth(networkId);
        if (ret != SUCCESS) {
            IAM_LOGE("failed to prepare remote auth");
        }

        callback->OnResult(ret, attr.Serialize());
    });

    return SUCCESS;
}

int32_t UserAuthService::PrepareRemoteAuth(const std::string &networkId,
    const sptr<IIamCallback> &callback)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    int32_t ret = PrepareRemoteAuthInner(networkId, callback);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to prepare remote auth");
        Attributes attr;
        callback->OnResult(ret, attr.Serialize());
    }

    IAM_LOGI("end");
    return SUCCESS;
}

bool UserAuthService::ProcessAuthParamForRemoteAuth(AuthParamInner &authParam, Authentication::AuthenticationPara &para,
    RemoteAuthParam &remoteAuthParam, std::string &localNetworkId)
{
    if (para.authType != PIN) {
        IAM_LOGE("remote auth only support pin auth");
        return false;
    }

    if (authParam.userId == INVALID_USER_ID) {
        IAM_LOGE("userid must be set for remote auth");
        return false;
    }

    bool completeRet = CompleteRemoteAuthParam(remoteAuthParam, localNetworkId);
    if (!completeRet) {
        IAM_LOGE("failed to complete remote auth param");
        return false;
    }

    if (remoteAuthParam.collectorTokenId.has_value()) {
        para.collectorTokenId = remoteAuthParam.collectorTokenId.value();
    } else {
        para.collectorTokenId = para.tokenId;
    }

    return true;
}

uint64_t UserAuthService::AuthRemoteUser(AuthParamInner &authParam, Authentication::AuthenticationPara &para,
    RemoteAuthParam &remoteAuthParam, const std::shared_ptr<ContextCallback> &contextCallback, ResultCode &failReason)
{
    IAM_LOGI("start");

    std::string localNetworkId;
    if (!DeviceManagerUtil::GetInstance().GetLocalDeviceNetWorkId(localNetworkId)) {
        IAM_LOGE("failed to get local network id");
        failReason = GENERAL_ERROR;
        return BAD_CONTEXT_ID;
    }

    if (!ProcessAuthParamForRemoteAuth(authParam, para, remoteAuthParam, localNetworkId)) {
        IAM_LOGE("failed to check remote auth param");
        failReason = INVALID_PARAMETERS;
        return BAD_CONTEXT_ID;
    }

    failReason = GENERAL_ERROR;

    if (remoteAuthParam.verifierNetworkId.value() == localNetworkId &&
        remoteAuthParam.collectorNetworkId.value() == localNetworkId) {
        IAM_LOGI("verifierNetworkId and collectorNetworkId are both local, start local remote auth");
        LocalRemoteAuthContextParam localRemoteAuthContextParam = {};
        localRemoteAuthContextParam.collectorNetworkId = remoteAuthParam.collectorNetworkId.value();
        return StartLocalRemoteAuthContext(para, localRemoteAuthContextParam, contextCallback);
    }

    if (remoteAuthParam.collectorNetworkId.value() == localNetworkId) {
        RemoteAuthInvokerContextParam remoteAuthInvokerContextParam = {};
        remoteAuthInvokerContextParam.verifierNetworkId = remoteAuthParam.verifierNetworkId.value();
        remoteAuthInvokerContextParam.collectorNetworkId = remoteAuthParam.collectorNetworkId.value();
        remoteAuthInvokerContextParam.tokenId = para.tokenId;
        remoteAuthInvokerContextParam.collectorTokenId = para.collectorTokenId;
        remoteAuthInvokerContextParam.callerName = para.callerName;
        remoteAuthInvokerContextParam.callerType = para.callerType;
        IAM_LOGI("start remote auth invoker context");
        return StartRemoteAuthInvokerContext(authParam, remoteAuthInvokerContextParam, contextCallback);
    }

    RemoteAuthContextParam remoteAuthContextParam = {};
    remoteAuthContextParam.authType = authParam.authType;
    remoteAuthContextParam.collectorNetworkId = remoteAuthParam.collectorNetworkId.value();
    remoteAuthContextParam.executorInfoMsg = {};
    int32_t dummyLastError = 0;
    IAM_LOGI("start remote auth context");
    return RemoteAuthService::GetInstance().StartRemoteAuthContext(
        para, remoteAuthContextParam, contextCallback, dummyLastError);
}

int32_t UserAuthService::Identify(const std::vector<uint8_t> &challenge, int32_t authType,
    const sptr<IIamCallback> &userAuthCallback, uint64_t &contextId)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    contextId = BAD_CONTEXT_ID;
    if (userAuthCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }
    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(userAuthCallback, TRACE_IDENTIFY);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        userAuthCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    if (static_cast<AuthType>(authType) == PIN) {
        IAM_LOGE("type not support %{public}d", authType);
        contextCallback->SetTraceAuthFinishReason("UserAuthService Identify IsAuthTypeEnable fail");
        contextCallback->OnResult(TYPE_NOT_SUPPORT, extraInfo);
        return GENERAL_ERROR;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Identify CheckPermission fail");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    Identification::IdentificationPara para = {};
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.authType = static_cast<AuthType>(authType);
    para.challenge = std::move(challenge);
    auto context = ContextFactory::CreateIdentifyContext(para, contextCallback);
    if (!ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Identify insert context fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }

    contextCallback->SetCleaner(ContextHelper::Cleaner(context));

    if (!context->Start()) {
        IAM_LOGE("failed to start identify");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Identify start context fail");
        contextCallback->OnResult(context->GetLatestError(), extraInfo);
        return GENERAL_ERROR;
    }
    contextId = context->GetContextId();
    return SUCCESS;
}

int32_t UserAuthService::CancelAuthOrIdentify(uint64_t contextId, int32_t cancelReason)
{
    IAM_LOGD("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    bool checkRet = !IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION);
    if (checkRet) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    auto context = ContextPool::Instance().Select(contextId).lock();
    if (context == nullptr) {
        IAM_LOGE("context not exist");
        return INVALID_CONTEXT_ID;
    }

    if (context->GetTokenId() != IpcCommon::GetAccessTokenId(*this)) {
        IAM_LOGE("failed to check tokenId");
        return CHECK_PERMISSION_FAILED;
    }

    if (cancelReason == CancelReason::MODAL_CREATE_ERROR || cancelReason == CancelReason::MODAL_RUN_ERROR) {
        IAM_LOGE("widget modal fault");
        UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "AuthWidget");
    }

    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(handler != nullptr, GENERAL_ERROR);
    handler->PostTask([context]() {
        if (!context->Stop()) {
            IAM_LOGE("failed to cancel auth or identify, ret%{public}d", context->GetLatestError());
        }
    });

    return SUCCESS;
}

int32_t UserAuthService::GetVersion(int32_t &version)
{
    IAM_LOGI("start");
    version = MINIMUM_VERSION;
    bool checkRet = !IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION);
    if (checkRet) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    version = CURRENT_VERSION;
    return SUCCESS;
}

int32_t UserAuthService::CheckAuthWidgetType(const std::vector<AuthType> &authType)
{
    if (authType.empty() || (authType.size() > MAX_AUTH_TYPE_SIZE)) {
        IAM_LOGE("invalid authType size:%{public}zu", authType.size());
        return INVALID_PARAMETERS;
    }
    const std::set<AuthType> WIDGET_AUTH_TYPE_VALID_SET = {AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT,
        AuthType::PRIVATE_PIN, AuthType::COMPANION_DEVICE};
    for (const auto &iter : authType) {
        if (WIDGET_AUTH_TYPE_VALID_SET.find(iter) == WIDGET_AUTH_TYPE_VALID_SET.end()) {
            IAM_LOGE("authType check fail:%{public}d", static_cast<int32_t>(iter));
            return TYPE_NOT_SUPPORT;
        }
    }
    std::set<AuthType> typeChecker(authType.begin(), authType.end());
    if (typeChecker.size() != authType.size()) {
        IAM_LOGE("duplicate auth type");
        return INVALID_PARAMETERS;
    }
    bool hasPin = false;
    bool hasPrivatePin = false;
    bool hasCompanionDevice = false;
    for (const auto &iter : authType) {
        if (iter == AuthType::PIN) {
            hasPin = true;
        } else if (iter == AuthType::PRIVATE_PIN) {
            hasPrivatePin = true;
        } else if (iter == AuthType::COMPANION_DEVICE) {
            hasCompanionDevice = true;
        }
    }
    if (hasPin && hasPrivatePin) {
        IAM_LOGE("pin and private pin not support");
        return INVALID_PARAMETERS;
    }
    if (hasCompanionDevice && (authType.size() != 1)) {
        IAM_LOGE("CompanionDevice cannot combine with other auth type");
        return INVALID_PARAMETERS;
    }
    return SUCCESS;
}

bool UserAuthService::CheckAuthTypeOnly(
    const std::vector<AuthType> &checkedTypes, const std::set<AuthType> &onlyContainTypes)
{
    return std::all_of(checkedTypes.begin(), checkedTypes.end(), [&onlyContainTypes](AuthType type) {
        return onlyContainTypes.find(type) != onlyContainTypes.end();
        });
}

bool UserAuthService::CheckPrivatePinEnroll(const std::vector<AuthType> &authType, std::vector<AuthType> &validType)
{
    bool hasPrivatePin = false;
    for (auto &iter : authType) {
        if (iter == AuthType::PRIVATE_PIN) {
            hasPrivatePin = true;
            break;
        }
    }
    if (!hasPrivatePin) {
        return true;
    }
    const size_t sizeTwo = 2;
    bool hasFace = false;
    bool hasFinger = false;
    for (const auto &iter : validType) {
        if (iter == AuthType::FACE) {
            hasFace = true;
        } else if (iter == AuthType::FINGERPRINT) {
            hasFinger = true;
        }
    }
    if (validType.size() == sizeTwo && hasFace && hasFinger) {
        return false;
    }
    return true;
}

int32_t UserAuthService::CheckCallerPermissionForPrivatePin(const AuthParamInner &authParam)
{
    bool hasPrivatePin = false;
    for (auto &iter : authParam.authTypes) {
        if (iter == AuthType::PRIVATE_PIN) {
            hasPrivatePin = true;
            break;
        }
    }
    if (!hasPrivatePin) {
        return SUCCESS;
    }
    if (IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        return SUCCESS;
    }
    if (IpcCommon::CheckPermission(*this, IS_SYSTEM_APP)) {
        return SUCCESS;
    }
    IAM_LOGE("CheckPermission failed");
    return CHECK_PERMISSION_FAILED;
}

int32_t UserAuthService::CheckCallerPermissionForUserId(const AuthParamInner &authParam)
{
    if (!authParam.isUserIdSpecified) {
        if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
            IAM_LOGE("CheckPermission failed");
            return CHECK_PERMISSION_FAILED;
        }
        return SUCCESS;
    }

    // inner api caller
    if (IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        return SUCCESS;
    }
    // native api caller
    int32_t userId = INVALID_USER_ID;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get callingUserId");
        return GENERAL_ERROR;
    }
    if (IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION) &&
        (IpcCommon::CheckPermission(*this, IS_SYSTEM_APP) || authParam.userId == userId)) {
        return SUCCESS;
    }
    IAM_LOGE("CheckPermission failed");
    return CHECK_PERMISSION_FAILED;
}

int32_t UserAuthService::CheckAuthWidgetParam(const AuthParamInner &authParam, const WidgetParamInner &widgetParam)
{
    if (widgetParam.navigationButtonText.empty()) {
        static const size_t authTypeTwo = 2;
        if ((authParam.authTypes.size() == authTypeTwo) &&
            CheckAuthTypeOnly(authParam.authTypes, {AuthType::FACE, AuthType::FINGERPRINT})) {
            IAM_LOGE("only face+finger not support");
            return INVALID_PARAMETERS;
        }
    }
    const size_t buttonTextMax = 60;
    if (UserAuthHelper::GetUtf8CharCount(widgetParam.navigationButtonText) > buttonTextMax) {
        IAM_LOGE("navigation button text is invalid");
        return INVALID_PARAMETERS;
    }
    if (widgetParam.title.empty() || UserAuthHelper::GetUtf8CharCount(widgetParam.title) > TITLE_MAX) {
        IAM_LOGE("title is invalid");
        return INVALID_PARAMETERS;
    }
    return SUCCESS;
}

int32_t UserAuthService::CheckAuthPermissionAndParam(const AuthParamInner &authParam,
    const WidgetParamInner &widgetParam, bool isBackgroundApplication)
{
    if (authParam.credentialIdList.size() > MAX_USER_CREDENTIAL_SIZE) {
        IAM_LOGE("bad credentialIdList size:%{public}zu", authParam.credentialIdList.size());
        return INVALID_PARAMETERS;
    }
    int32_t checkRet = CheckWindowMode(widgetParam);
    if (checkRet != SUCCESS) {
        IAM_LOGE("CheckWindowMode failed");
        return checkRet;
    }
    if (CheckCallerPermissionForPrivatePin(authParam) != SUCCESS) {
        IAM_LOGE("CheckCallerPermissionForPrivatePin failed");
        return CHECK_PERMISSION_FAILED;
    }
    if (CheckCallerPermissionForUserId(authParam) != SUCCESS) {
        IAM_LOGE("CheckPermission failed");
        return CHECK_PERMISSION_FAILED;
    }
    if (isBackgroundApplication && (!IpcCommon::CheckPermission(*this, USER_AUTH_FROM_BACKGROUND))) {
        IAM_LOGE("failed to check foreground application");
        return CHECK_PERMISSION_FAILED;
    }
    int32_t ret = CheckAuthWidgetType(authParam.authTypes);
    if (ret != SUCCESS) {
        IAM_LOGE("CheckAuthWidgetType fail.");
        return ret;
    }
    if (!CheckAuthTrustLevel(authParam.authTrustLevel, authParam.authType)) {
        IAM_LOGE("authTrustLevel is not in correct range");
        return ResultCode::TRUST_LEVEL_NOT_SUPPORT;
    }

    return CheckAuthWidgetParam(authParam, widgetParam);
}

int32_t UserAuthService::CheckWindowMode(const WidgetParamInner &widgetParam)
{
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP) &&
        (widgetParam.windowMode == WindowModeType::NONE_INTERRUPTION_DIALOG_BOX)) {
        IAM_LOGE("the caller is not a system application.");
        return CHECK_SYSTEM_APP_FAILED;
    }
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP) &&
        (widgetParam.windowMode != WindowModeType::UNKNOWN_WINDOW_MODE)) {
        IAM_LOGE("normal app can't set window mode.");
        return INVALID_PARAMETERS;
    }
    return SUCCESS;
}

uint64_t UserAuthService::StartWidgetContext(const std::shared_ptr<ContextCallback> &contextCallback,
    const AuthParamInner &authParam, const WidgetParamInner &widgetParam, std::vector<AuthType> &validType,
    ContextFactory::AuthWidgetContextPara &para, const sptr<IModalCallback> &modalCallback)
{
    HILOG_COMM_INFO("auth service start context useId: %{public}d, authType: %{public}d,"
        " atl: %{public}d, callerName: %{public}s, isBackgroundApplication %{public}d",
        authParam.userId, authParam.authType, authParam.authTrustLevel,
        para.callerName.c_str(), para.isBackgroundApplication);
    Attributes extraInfo;
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.isOsAccountVerified = IpcCommon::IsOsAccountVerified(para.userId);
    if (!AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para)) {
        IAM_LOGE("init widgetContext failed");
        contextCallback->SetTraceAuthFinishReason("UserAuthService InitWidgetContextParam fail");
        contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    sptr<IRemoteAuthCallback> remoteAuthCallback = nullptr;
    if (authParam.remoteTokenId.has_value()) {
        remoteAuthCallback =
            RemoteAuthCallbackManager::GetInstance().GetRemoteAuthCallback(authParam.remoteTokenId.value());
        if (remoteAuthCallback == nullptr) {
            IAM_LOGE("get remoteAuthCallback failed");
            contextCallback->SetTraceAuthFinishReason("UserAuthService GetRemoteAuthCallback fail");
            contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
            return BAD_CONTEXT_ID;
        }
        std::string callerName =
            RemoteAuthCallbackManager::GetInstance().GetRemoteAuthCallerName(authParam.remoteTokenId.value());
        if (!callerName.empty()) {
            para.remoteCallerName = callerName;
        }
    }
    auto context = ContextFactory::CreateWidgetContext(para, contextCallback, modalCallback, remoteAuthCallback);
    if (context == nullptr || !Insert2ContextPool(context)) {
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget insert context fail");
        contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    if (!context->Start()) {
        int32_t errorCode = context->GetLatestError();
        IAM_LOGE("start widget context fail %{public}d", errorCode);
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget start context fail");
        contextCallback->OnResult(errorCode, extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

int32_t UserAuthService::CheckSkipLockedBiometricAuth(ContextFactory::AuthWidgetContextPara &para,
    const AuthParamInner &authParam, const WidgetParamInner &widgetParam, std::vector<AuthType> &validType)
{
    if (validType.empty()) {
        IAM_LOGE("validType size is 0");
        return TYPE_NOT_SUPPORT;
    }
    for (auto iter = validType.begin(); iter != validType.end();) {
        AuthType type = *iter;
        ContextFactory::AuthProfile profile = {};
        if (!AuthWidgetHelper::GetUserAuthProfile(para.userId, type, profile, authParam.credentialIdList)) {
            IAM_LOGE("get user auth profile failed");
            iter = validType.erase(iter);
            continue;
        }
        para.authProfileMap[type] = profile;
        if (type == AuthType::PIN || type == AuthType::PRIVATE_PIN) {
            WidgetClient::Instance().SetPinSubType(static_cast<PinSubType>(profile.pinSubType));
        } else if (type == AuthType::FINGERPRINT) {
            WidgetClient::Instance().SetSensorInfo(profile.sensorInfo);
        }
        if (authParam.skipLockedBiometricAuth && profile.remainTimes == 0 && type != AuthType::PIN &&
            type != AuthType::PRIVATE_PIN) {
            iter = validType.erase(iter);
            para.authProfileMap.erase(type);
        } else {
            ++iter;
        }
    }
    if (!widgetParam.navigationButtonText.empty()) {
        if (validType.empty()) {
            IAM_LOGE("validType size:%{public}zu, return cancel from widget", validType.size());
            return CANCELED_FROM_WIDGET;
        }
    }

    if (validType.empty()) {
        IAM_LOGE("validType is null, return lock");
        return LOCKED;
    }
    return SUCCESS;
}

std::vector<AuthType> UserAuthService::GetAuthTypesFromCredentialIds(const AuthParamInner &authParam)
{
    if (authParam.credentialIdList.empty()) {
        return authParam.authTypes;
    }

    auto credList = authParam.credentialIdList;
    std::sort(credList.begin(), credList.end());
    credList.erase(std::unique(credList.begin(), credList.end()), credList.end());
 
    std::vector<AuthType> authTypeList = {};
    for (auto credId : credList) {
        std::shared_ptr<CredentialInfoInterface> credInfo;
        int32_t ret = UserIdmDatabase::Instance().GetCredentialInfoById(credId, credInfo);
        if (ret != SUCCESS) {
            IAM_LOGE("GetCredentialInfoById failed, %{public}d", ret);
            continue;
        }
        authTypeList.push_back(credInfo->GetAuthType());
    }
    return authTypeList;
}

void UserAuthService::FilterFaceNotAvailable(ContextFactory::AuthWidgetContextPara &para,
    std::vector<AuthType> &validType)
{
    if (validType.size() == 1) {
        return;
    }
    auto faceIter = para.authProfileMap.find(AuthType::FACE);
    if (faceIter != para.authProfileMap.end() && faceIter->second.cameraStatus == CameraStatus::CAMERA_NOT_AVAILABLE) {
        validType.erase(std::remove(validType.begin(), validType.end(), AuthType::FACE), validType.end());
        para.authProfileMap.erase(AuthType::FACE);
    }
}

int32_t UserAuthService::CheckValidSolution(ContextFactory::AuthWidgetContextPara &para,
    const AuthParamInner &authParam, const WidgetParamInner &widgetParam, std::vector<AuthType> &validType)
{
    std::vector<AuthType> authTypes = GetAuthTypesFromCredentialIds(authParam);
    int32_t ret = AuthWidgetHelper::CheckValidSolution(
        para.userId, authTypes, authParam.authTrustLevel, validType);
    if (ret != SUCCESS) {
        IAM_LOGE("CheckValidSolution fail %{public}d", ret);
        return ret;
    }
    if (!widgetParam.navigationButtonText.empty() &&
        !CheckAuthTypeOnly(validType, {AuthType::FACE, AuthType::FINGERPRINT})) {
        IAM_LOGE("navigationButtonText check fail, validType.size:%{public}zu", validType.size());
        return INVALID_PARAMETERS;
    }
    if (widgetParam.windowMode == FULLSCREEN &&
        (CheckAuthTypeOnly(validType, {AuthType::FACE, AuthType::FINGERPRINT}))) {
        IAM_LOGE("Single fingerprint or single face does not support full screen");
        return INVALID_PARAMETERS;
    }
    if (!CheckPrivatePinEnroll(authParam.authTypes, validType)) {
        IAM_LOGE("check privatePin enroll error");
        return INVALID_PARAMETERS;
    }
    if (!IpcCommon::IsOsAccountVerified(para.userId)) {
        IAM_LOGI("auth userId: %{public}u, biometric authentication has been filtered.", para.userId);
        validType.erase(std::remove_if(validType.begin(), validType.end(), [](AuthType authType) {
            return authType != AuthType::PIN && authType != AuthType::PRIVATE_PIN;
            }), validType.end());
    }
    return CheckSkipLockedBiometricAuth(para, authParam, widgetParam, validType);
}

int32_t UserAuthService::GetCallerInfo(bool isUserIdSpecified, int32_t userId,
    ContextFactory::AuthWidgetContextPara &para, std::shared_ptr<ContextCallback> &contextCallback)
{
    static_cast<void>(IpcCommon::GetCallerName(*this, para.callerName, para.callerType));
    contextCallback->SetTraceCallerName(para.callerName);
    contextCallback->SetTraceCallerType(para.callerType);
    static_cast<void>(IpcCommon::GetCallingAppID(*this, para.callingAppID));

    if (para.sdkVersion < INNER_API_VERSION_10000 && para.callerType == Security::AccessToken::TOKEN_HAP &&
        (!IpcCommon::CheckForegroundApplication(para.callerName))) {
        para.isBackgroundApplication = true;
    }
    contextCallback->SetTraceIsBackgroundApplication(para.isBackgroundApplication);

    if (isUserIdSpecified) {
        para.userId = userId;
        contextCallback->SetTraceUserId(para.userId);
        return SUCCESS;
    }
    if (IpcCommon::GetCallingUserId(*this, para.userId) != SUCCESS) {
        IAM_LOGE("get callingUserId failed");
        return GENERAL_ERROR;
    }
    contextCallback->SetTraceUserId(para.userId);
    return SUCCESS;
}

void UserAuthService::ProcessPinExpired(int32_t ret, const AuthParamInner &authParam,
    std::vector<AuthType> &validType, ContextFactory::AuthWidgetContextPara &para)
{
    if (ret != PIN_EXPIRED) {
        return;
    }
    para.isPinExpired = true;
    bool hasPrivatePin = false;
    for (auto &iter : authParam.authTypes) {
        if (iter == AuthType::PRIVATE_PIN) {
            hasPrivatePin = true;
            break;
        }
    }
    if (hasPrivatePin) {
        validType.clear();
        validType.emplace_back(AuthType::PRIVATE_PIN);
    } else {
        validType.emplace_back(AuthType::PIN);
    }
}

int32_t UserAuthService::StartAuthWidget(AuthParamInner &authParam, WidgetParamInner &widgetParam,
    ContextFactory::AuthWidgetContextPara &para, std::shared_ptr<ContextCallback> &contextCallback,
    const sptr<IModalCallback> &modalCallback, uint64_t &contextId)
{
    IAM_LOGI("start");
    Attributes extraInfo;
    std::vector<AuthType> validType;
    int32_t checkRet = CheckValidSolution(para, authParam, widgetParam, validType);
    if (checkRet != SUCCESS && checkRet != PIN_EXPIRED) {
        IAM_LOGE("check valid solution failed");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget CheckValidSolution fail");
        contextCallback->OnResult(checkRet, extraInfo);
        return checkRet;
    }
    ProcessPinExpired(checkRet, authParam, validType, para);
    FilterFaceNotAvailable(para, validType);
    ProcessWidgetSessionExclusive();

    contextId = StartWidgetContext(contextCallback, authParam, widgetParam, validType, para, modalCallback);
    if (contextId == BAD_CONTEXT_ID) {
        IAM_LOGE("StartWidgetContext fail");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthService::AuthWidget(int32_t apiVersion, const IpcAuthParamInner &ipcAuthParamInner,
    const IpcWidgetParamInner &ipcWidgetParamInner, const sptr<IIamCallback> &userAuthCallback,
    const sptr<IModalCallback> &modalCallback, uint64_t &contextId)
{
    IAM_LOGI("start %{public}d authTrustLevel:%{public}u", apiVersion, ipcAuthParamInner.authTrustLevel);
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    InitAuthParam(ipcAuthParamInner, authParam);
    InitWidgetParam(ipcWidgetParamInner, widgetParam);
    auto contextCallback = GetAuthContextCallback(apiVersion, authParam, widgetParam, userAuthCallback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return GENERAL_ERROR;
    }
    ContextFactory::AuthWidgetContextPara para;
    para.sdkVersion = apiVersion;
    Attributes extraInfo;
    int32_t checkRet = GetCallerInfo(authParam.isUserIdSpecified, authParam.userId, para, contextCallback);
    if (checkRet != SUCCESS) {
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget GetCallerInfo fail");
        contextCallback->OnResult(checkRet, extraInfo);
        return checkRet;
    }
    checkRet = CheckAuthPermissionAndParam(authParam, widgetParam, para.isBackgroundApplication);
    if (checkRet != SUCCESS) {
        IAM_LOGE("check permission and auth widget param failed");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget CheckAuthPermissionAndParam fail");
        contextCallback->OnResult(checkRet, extraInfo);
        return checkRet;
    }

    if (AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo) == SUCCESS) {
        IAM_LOGE("check reuse unlock result success");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget CheckReuseUnlockResult success");
        contextCallback->OnResult(SUCCESS, extraInfo);
        contextId = REUSE_AUTH_RESULT_CONTEXT_ID;
        return SUCCESS;
    }

    return StartAuthWidget(authParam, widgetParam, para, contextCallback, modalCallback, contextId);
}

void UserAuthService::ProcessWidgetSessionExclusive()
{
    auto contextList = ContextPool::Instance().Select(ContextType::WIDGET_AUTH_CONTEXT);
    for (const auto &context : contextList) {
        if (auto ctx = context.lock(); ctx != nullptr) {
            IAM_LOGE("widget session exclusive, force stop the old context ****%{public}hx",
                static_cast<uint16_t>(ctx->GetContextId()));
            ctx->Stop();
        }
    }
}

bool UserAuthService::Insert2ContextPool(const std::shared_ptr<Context> &context)
{
    bool ret = false;
    const int32_t retryTimes = 3;
    for (auto i = 0; i < retryTimes; i++) {
        ret = ContextPool::Instance().Insert(context);
        if (ret) {
            break;
        }
    }
    IAM_LOGI("insert context to pool, retry %{public}d times", retryTimes);
    return ret;
}

std::shared_ptr<ContextCallback> UserAuthService::GetAuthContextCallback(int32_t apiVersion,
    const AuthParamInner &authParam, const WidgetParamInner &widgetParam,
    const sptr<IIamCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return nullptr;
    }
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER_BEHAVIOR);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        Attributes extraInfo;
        callback->OnResult(ResultCode::GENERAL_ERROR, extraInfo.Serialize());
        return nullptr;
    }
    contextCallback->SetTraceSdkVersion(apiVersion);
    contextCallback->SetTraceAuthTrustLevel(authParam.authTrustLevel);

    uint32_t authWidgetType = 0;
    for (const auto authType : authParam.authTypes) {
        authWidgetType |= static_cast<uint32_t>(authType);
    }
    static const uint32_t bitWindowMode = 0x40000000;
    if (widgetParam.windowMode == FULLSCREEN) {
        authWidgetType |= bitWindowMode;
    }
    static const uint32_t bitNavigation = 0x80000000;
    if (!widgetParam.navigationButtonText.empty()) {
        authWidgetType |= bitNavigation;
    }
    IAM_LOGI("SetTraceAuthWidgetType %{public}08x", authWidgetType);
    contextCallback->SetTraceAuthWidgetType(authWidgetType);
    uint32_t traceReuseMode = 0;
    uint64_t traceReuseDuration = 0;
    if (authParam.reuseUnlockResult.isReuse) {
        traceReuseMode = authParam.reuseUnlockResult.reuseMode;
        traceReuseDuration = authParam.reuseUnlockResult.reuseDuration;
    }
    contextCallback->SetTraceReuseUnlockResultMode(traceReuseMode);
    contextCallback->SetTraceReuseUnlockResultDuration(traceReuseDuration);
    return contextCallback;
}

int32_t UserAuthService::Notice(int32_t noticeType, const std::string &eventData)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP)) {
        IAM_LOGE("the caller is not a system application");
        return ResultCode::CHECK_SYSTEM_APP_FAILED;
    }

    if (!IpcCommon::CheckPermission(*this, SUPPORT_USER_AUTH)) {
        IAM_LOGE("failed to check permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
    }
    return WidgetClient::Instance().OnNotice(static_cast<NoticeType>(noticeType), eventData);
}

int32_t UserAuthService::RegisterWidgetCallback(int32_t version, const sptr<IWidgetCallback> &widgetCallback)
{
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP)) {
        IAM_LOGE("the caller is not a system application");
        return ResultCode::CHECK_SYSTEM_APP_FAILED;
    }

    if (!IpcCommon::CheckPermission(*this, SUPPORT_USER_AUTH)) {
        IAM_LOGE("CheckPermission failed, no permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
    }

    uint32_t tokenId = IpcCommon::GetTokenId(*this);
    IAM_LOGE("RegisterWidgetCallback tokenId %{public}s", GET_MASKED_STRING(tokenId).c_str());

    int32_t curVersion = std::stoi(NOTICE_VERSION_STR);
    if (version != curVersion) {
        return ResultCode::INVALID_PARAMETERS;
    }
    if (widgetCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }
    WidgetClient::Instance().SetWidgetCallback(widgetCallback);
    WidgetClient::Instance().SetAuthTokenId(tokenId);
    return ResultCode::SUCCESS;
}

int32_t UserAuthService::GetEnrolledStateImpl(int32_t apiVersion, int32_t authType,
    IpcEnrolledState &ipcEnrolledState)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    if (apiVersion < API_VERSION_12) {
        IAM_LOGE("failed to check apiVersion");
        return TYPE_NOT_SUPPORT;
    }

    int32_t userId = INVALID_USER_ID;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get callingUserId");
        return GENERAL_ERROR;
    }

    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return GENERAL_ERROR;
    }
    HdiEnrolledState hdiEnrolledState = {};
    int32_t result = hdi->GetEnrolledState(userId, static_cast<HdiAuthType>(authType), hdiEnrolledState);
    if (result == NOT_ENROLLED) {
        IAM_LOGI("credential is not enrolled, userId:%{public}d authType:%{public}d", userId, authType);
        return result;
    }
    if (result != SUCCESS) {
        IAM_LOGE("failed to get enrolled state,userId:%{public}d authType:%{public}d", userId, authType);
        return result;
    }
    ipcEnrolledState.credentialCount = hdiEnrolledState.credentialCount;
    ipcEnrolledState.credentialDigest = hdiEnrolledState.credentialDigest;
    if (apiVersion < INNER_API_VERSION_10000) {
        ipcEnrolledState.credentialDigest = hdiEnrolledState.credentialDigest & UINT16_MAX;
    }
    return SUCCESS;
}

int32_t UserAuthService::GetEnrolledState(int32_t apiVersion, int32_t authType,
    IpcEnrolledState &ipcEnrolledState, int32_t &funcResult)
{
    IAM_LOGI("start");
    funcResult = GetEnrolledStateImpl(apiVersion, authType, ipcEnrolledState);
    return SUCCESS;
}

int32_t UserAuthService::GetAuthLockState(int32_t authType,
    const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback)
{
    IAM_LOGD("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExecutorPropertyCallback != nullptr, INVALID_PARAMETERS);
    Attributes values;
    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        getExecutorPropertyCallback->OnGetExecutorPropertyResult(CHECK_PERMISSION_FAILED, values.Serialize());
        return SUCCESS;
    }

    int32_t userId = INVALID_USER_ID;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get callingUserId");
        getExecutorPropertyCallback->OnGetExecutorPropertyResult(GENERAL_ERROR, values.Serialize());
        return SUCCESS;
    }
    
    std::vector<Attributes::AttributeKey> attrKeys;
    attrKeys.push_back(Attributes::ATTR_REMAIN_TIMES);
    attrKeys.push_back(Attributes::ATTR_FREEZING_TIME);

    return GetPropertyHelper(userId, AuthType(authType), attrKeys, getExecutorPropertyCallback);
}

int32_t UserAuthService::RegistUserAuthSuccessEventListener(const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    int32_t result = AuthEventListenerManager::GetInstance().RegistEventListener(listener);
    if (result != SUCCESS) {
        IAM_LOGE("failed to regist auth event listener");
        return result;
    }

    return SUCCESS;
}

int32_t UserAuthService::UnRegistUserAuthSuccessEventListener(const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    int32_t result = AuthEventListenerManager::GetInstance().UnRegistEventListener(listener);
    if (result != SUCCESS) {
        IAM_LOGE("failed to unregist auth event listener");
        return result;
    }

    return SUCCESS;
}

int32_t SetPinAlgorithmsProperty(const IpcGlobalConfigParam &ipcGlobalConfigParam, HdiGlobalConfigParam &paramConfig)
{
    if (ipcGlobalConfigParam.authTypes.size() != 1 || ipcGlobalConfigParam.authTypes[0] != PIN) {
        IAM_LOGE("bad authTypes for PIN_EXPIRED_PERIOD");
        return INVALID_PARAMETERS;
    }
    if (ipcGlobalConfigParam.value.pinAlgoType == PinEncrypAlgoType::AES_GCM) {
        const int32_t pinAlgoAes = 3;
        paramConfig.type = pinAlgoAes;
    } else if (ipcGlobalConfigParam.value.pinAlgoType == PinEncrypAlgoType::SM4) {
        const int32_t pinAlgoSM4 = 4;
        paramConfig.type = pinAlgoSM4;
    } else {
        IAM_LOGE("bad pinAlgoType value:%{public}d", ipcGlobalConfigParam.value.pinAlgoType);
        return INVALID_PARAMETERS;
    }
    return SUCCESS;
}

int32_t UserAuthService::SetGlobalConfigParam(const IpcGlobalConfigParam &ipcGlobalConfigParam)
{
    IAM_LOGI("start, GlobalConfigType is %{public}d, userIds size %{public}zu, authTypes size %{public}zu",
        ipcGlobalConfigParam.type, ipcGlobalConfigParam.userIds.size(), ipcGlobalConfigParam.authTypes.size());
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) ||
        !IpcCommon::CheckPermission(*this, ENTERPRISE_DEVICE_MGR)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (ipcGlobalConfigParam.userIds.size() > MAX_USER || ipcGlobalConfigParam.authTypes.size() > MAX_AUTH_TYPE_SIZE ||
        ipcGlobalConfigParam.authTypes.size() == 0) {
        IAM_LOGE("bad global config param");
        return INVALID_PARAMETERS;
    }

    HdiGlobalConfigParam paramConfig = {};
    switch (static_cast<GlobalConfigType>(ipcGlobalConfigParam.type)) {
        case GlobalConfigType::PIN_EXPIRED_PERIOD:
            if (ipcGlobalConfigParam.authTypes.size() != 1 || ipcGlobalConfigParam.authTypes[0] != PIN) {
                IAM_LOGE("bad authTypes for PIN_EXPIRED_PERIOD");
                return INVALID_PARAMETERS;
            }
            paramConfig.value.pinExpiredPeriod = ipcGlobalConfigParam.value.pinExpiredPeriod;
            break;
        case GlobalConfigType::ENABLE_STATUS:
            paramConfig.value.enableStatus = ipcGlobalConfigParam.value.enableStatus;
            break;
        case GlobalConfigType::PIN_ALGO_TYPE:
            if (SetPinAlgorithmsProperty(ipcGlobalConfigParam, paramConfig) != SUCCESS) {
                return INVALID_PARAMETERS;
            }
            break;
        default:
            IAM_LOGE("bad global config type");
            return INVALID_PARAMETERS;
    }
    if (static_cast<GlobalConfigType>(ipcGlobalConfigParam.type) != GlobalConfigType::PIN_ALGO_TYPE) {
        paramConfig.type = static_cast<HdiGlobalConfigType>(ipcGlobalConfigParam.type);
    }
    paramConfig.userIds = ipcGlobalConfigParam.userIds;
    for (const auto authType : ipcGlobalConfigParam.authTypes) {
        paramConfig.authTypes.push_back(static_cast<AuthType>(authType));
    }
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, GENERAL_ERROR);
    int32_t result = hdi->SetGlobalConfigParam(paramConfig);
    IF_FALSE_LOGE_AND_RETURN_VAL(result == SUCCESS, result);

    return SUCCESS;
}

bool UserAuthService::CompleteRemoteAuthParam(RemoteAuthParam &remoteAuthParam, const std::string &localNetworkId)
{
    IAM_LOGI("start");
    if (remoteAuthParam.verifierNetworkId.has_value() && remoteAuthParam.verifierNetworkId->size() !=
        NETWORK_ID_LENGTH) {
        IAM_LOGE("invalid verifierNetworkId size");
        return false;
    }

    if (remoteAuthParam.collectorNetworkId.has_value() && remoteAuthParam.collectorNetworkId->size() !=
        NETWORK_ID_LENGTH) {
        IAM_LOGE("invalid collectorNetworkId size");
        return false;
    }

    if (!remoteAuthParam.verifierNetworkId.has_value() && !remoteAuthParam.collectorNetworkId.has_value()) {
        IAM_LOGE("both verifierNetworkId and collectorNetworkId are not set");
        return false;
    }

    if (!remoteAuthParam.verifierNetworkId.has_value()) {
        IAM_LOGI("verifierNetworkId not set, use local networkId as verifierNetworkId");
        remoteAuthParam.verifierNetworkId = localNetworkId;
    }

    if (!remoteAuthParam.collectorNetworkId.has_value()) {
        IAM_LOGI("collectorNetworkId not set, use local networkId as collectorNetworkId");
        remoteAuthParam.collectorNetworkId = localNetworkId;
    }

    if (remoteAuthParam.verifierNetworkId.value() != localNetworkId &&
        remoteAuthParam.collectorNetworkId.value() != localNetworkId) {
        IAM_LOGE("both verifierNetworkId and collectorNetworkId are not local networkId");
        return false;
    }

    if (remoteAuthParam.verifierNetworkId.value() == remoteAuthParam.collectorNetworkId.value() &&
        remoteAuthParam.verifierNetworkId.value() != localNetworkId) {
        IAM_LOGE("verifierNetworkId and collectorNetworkId are the same and not local networkId");
        return false;
    }

    if (remoteAuthParam.collectorNetworkId.value() != localNetworkId && !remoteAuthParam.collectorTokenId.has_value()) {
        IAM_LOGE("collectorNetworkId is not local networkId, collectorTokenId not set");
        return false;
    }

    if (remoteAuthParam.collectorNetworkId.value() == localNetworkId && !remoteAuthParam.collectorTokenId.has_value()) {
        IAM_LOGI("collectorNetworkId is local networkId, update collectorTokenId with caller token id");
        remoteAuthParam.collectorTokenId = IpcCommon::GetAccessTokenId(*this);
    }

    IAM_LOGI("success");
    return true;
}

bool UserAuthService::GetAuthTokenAttr(const HdiUserAuthTokenPlain &tokenPlain, const std::vector<uint8_t> &rootSecret,
    Attributes &extraInfo)
{
    bool setTokenVersionRet = extraInfo.SetUint32Value(Attributes::ATTR_TOKEN_VERSION, tokenPlain.version);
    IF_FALSE_LOGE_AND_RETURN_VAL(setTokenVersionRet == true, false);
    bool setUserIdRet = extraInfo.SetInt32Value(Attributes::ATTR_USER_ID, tokenPlain.userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setUserIdRet == true, false);
    bool setChallengeRet = extraInfo.SetUint8ArrayValue(Attributes::ATTR_CHALLENGE, tokenPlain.challenge);
    IF_FALSE_LOGE_AND_RETURN_VAL(setChallengeRet == true, false);
    bool setTimeStampRet = extraInfo.SetUint64Value(Attributes::ATTR_TOKEN_TIME_INTERVAL, tokenPlain.timeInterval);
    IF_FALSE_LOGE_AND_RETURN_VAL(setTimeStampRet == true, false);
    bool setTrustLevelRet = extraInfo.SetUint32Value(Attributes::ATTR_AUTH_TRUST_LEVEL, tokenPlain.authTrustLevel);
    IF_FALSE_LOGE_AND_RETURN_VAL(setTrustLevelRet == true, false);
    bool setAuthTypeRet = extraInfo.SetInt32Value(Attributes::ATTR_AUTH_TYPE, tokenPlain.authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthTypeRet == true, false);
    bool setTokenTypeRet = extraInfo.SetInt32Value(Attributes::ATTR_TOKEN_TYPE, tokenPlain.tokenType);
    IF_FALSE_LOGE_AND_RETURN_VAL(setTokenTypeRet == true, false);
    bool setSecureUidRet = extraInfo.SetUint64Value(Attributes::ATTR_SEC_USER_ID, tokenPlain.secureUid);
    IF_FALSE_LOGE_AND_RETURN_VAL(setSecureUidRet == true, false);
    bool setEnrolledIdRet = extraInfo.SetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, tokenPlain.enrolledId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setEnrolledIdRet == true, false);
    bool setCredentialIdRet = extraInfo.SetUint64Value(Attributes::ATTR_CREDENTIAL_ID, tokenPlain.credentialId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setCredentialIdRet == true, false);
    if (rootSecret.size() != 0) {
        bool setRootSecret = extraInfo.SetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, rootSecret);
        IF_FALSE_LOGE_AND_RETURN_VAL(setRootSecret == true, false);
    }
    return true;
}

int32_t UserAuthService::VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
    const sptr<IVerifyTokenCallback> &verifyTokenCallback)
{
    IAM_LOGI("start, duration:%{public}" PRIu64 ", tokenIn size:%{public}zu.", allowableDuration, tokenIn.size());
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(verifyTokenCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    if (tokenIn.size() == 0 || tokenIn.data() == nullptr) {
        IAM_LOGE("bad parameter");
        verifyTokenCallback->OnVerifyTokenResult(INVALID_PARAMETERS, extraInfo.Serialize());
        return INVALID_PARAMETERS;
    }
    if (!IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER)) {
        IAM_LOGE("failed to check permission");
        verifyTokenCallback->OnVerifyTokenResult(CHECK_PERMISSION_FAILED, extraInfo.Serialize());
        return CHECK_PERMISSION_FAILED;
    }
    if (IpcCommon::GetDirectCallerType(*this) != Security::AccessToken::TOKEN_NATIVE &&
        !IpcCommon::CheckPermission(*this, IS_SYSTEM_APP)) {
        IAM_LOGE("caller is not systemApp.");
        verifyTokenCallback->OnVerifyTokenResult(CHECK_SYSTEM_APP_FAILED, extraInfo.Serialize());
        return CHECK_SYSTEM_APP_FAILED;
    }

    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        verifyTokenCallback->OnVerifyTokenResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }

    HdiUserAuthTokenPlain tokenPlain = {};
    std::vector<uint8_t> rootSecret = {};
    int32_t result = hdi->VerifyAuthToken(tokenIn, allowableDuration, tokenPlain, rootSecret);
    if (result != SUCCESS) {
        IAM_LOGE("VerifyAuthToken failed result:%{public}d", result);
        verifyTokenCallback->OnVerifyTokenResult(result, extraInfo.Serialize());
        return result;
    }
    if (!GetAuthTokenAttr(tokenPlain, rootSecret, extraInfo)) {
        IAM_LOGE("GetAuthTokenAttr failed");
        verifyTokenCallback->OnVerifyTokenResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    verifyTokenCallback->OnVerifyTokenResult(SUCCESS, extraInfo.Serialize());
    return SUCCESS;
}

int32_t UserAuthService::QueryReusableAuthResult(const IpcAuthParamInner &ipcAuthParamInner,
    std::vector<uint8_t> &token)
{
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    if (!(IpcCommon::GetDirectCallerType(*this) == Security::AccessToken::TOKEN_HAP &&
        IpcCommon::CheckPermission(*this, IS_SYSTEM_APP))) {
        IAM_LOGE("caller is not systemApp.");
        return CHECK_SYSTEM_APP_FAILED;
    }

    AuthParamInner authParam = {};
    InitAuthParam(ipcAuthParamInner, authParam);
    if (!authParam.isUserIdSpecified) {
        if (IpcCommon::GetCallingUserId(*this, authParam.userId) != SUCCESS) {
            IAM_LOGE("failed to get callingUserId");
            return GENERAL_ERROR;
        }
    }

    HdiReuseUnlockInfo reuseResultInfo = {};
    int32_t result = AuthWidgetHelper::QueryReusableAuthResult(authParam.userId, authParam, reuseResultInfo);
    if (result != SUCCESS) {
        IAM_LOGE("CheckReuseUnlockResult failed result:%{public}d userId:%{public}d", result,
            ipcAuthParamInner.userId);
        return result;
    }

    token = reuseResultInfo.token;
    return SUCCESS;
}

int32_t UserAuthService::RegisterRemoteAuthCallback(const sptr<IRemoteAuthCallback> &remoteAuthCallback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(remoteAuthCallback != nullptr, INVALID_PARAMETERS);
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP)) {
        IAM_LOGE("the caller is not a system application");
        return ResultCode::CHECK_SYSTEM_APP_FAILED;
    }

    if (!IpcCommon::CheckPermission(*this, SUPPORT_USER_AUTH)) {
        IAM_LOGE("CheckPermission failed, no permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
    }

    uint32_t tokenId = IpcCommon::GetAccessTokenId(*this);
    std::string callerName;
    int32_t callerType;
    if ((!IpcCommon::GetCallerName(*this, callerName, callerType))) {
        IAM_LOGE("get bundle name fail");
        return GENERAL_ERROR;
    }

    return RemoteAuthCallbackManager::GetInstance().AddRemoteAuthCallback(tokenId, remoteAuthCallback, callerName);
}

int32_t UserAuthService::UnregisterRemoteAuthCallback()
{
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP)) {
        IAM_LOGE("the caller is not a system application");
        return ResultCode::CHECK_SYSTEM_APP_FAILED;
    }

    if (!IpcCommon::CheckPermission(*this, SUPPORT_USER_AUTH)) {
        IAM_LOGE("CheckPermission failed, no permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
    }

    uint32_t tokenId = IpcCommon::GetAccessTokenId(*this);
    return RemoteAuthCallbackManager::GetInstance().DelRemoteAuthCallback(tokenId);
}

void UserAuthService::InitAuthParam(const IpcAuthParamInner &ipcAuthParam, AuthParamInner &authParam)
{
    authParam.userId = ipcAuthParam.userId;
    authParam.isUserIdSpecified = ipcAuthParam.isUserIdSpecified;
    authParam.challenge = ipcAuthParam.challenge;
    authParam.authType = static_cast<AuthType>(ipcAuthParam.authType);
    authParam.authTypes.resize(ipcAuthParam.authTypes.size());
    std::transform(ipcAuthParam.authTypes.begin(), ipcAuthParam.authTypes.end(),
        authParam.authTypes.begin(), [](int32_t authType) {
        return static_cast<AuthType>(authType);
    });
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(ipcAuthParam.authTrustLevel);
    authParam.authIntent = static_cast<AuthIntent>(ipcAuthParam.authIntent);
    authParam.skipLockedBiometricAuth = ipcAuthParam.skipLockedBiometricAuth;
    authParam.credentialIdList = ipcAuthParam.credentialIdList;
    authParam.reuseUnlockResult.isReuse = ipcAuthParam.reuseUnlockResult.isReuse;
    authParam.reuseUnlockResult.reuseMode = static_cast<ReuseMode>(ipcAuthParam.reuseUnlockResult.reuseMode);
    authParam.reuseUnlockResult.reuseDuration = ipcAuthParam.reuseUnlockResult.reuseDuration;
    if (ipcAuthParam.isHasRemoteTokenId) {
        authParam.remoteTokenId = ipcAuthParam.remoteTokenId;
    }
}

void UserAuthService::InitRemoteAuthParam(const IpcRemoteAuthParam &ipcRemoteAuthParam,
    std::optional<RemoteAuthParam> &remoteAuthParam)
{
    if (ipcRemoteAuthParam.isHasRemoteAuthParam) {
        remoteAuthParam = RemoteAuthParam{};
        remoteAuthParam->verifierNetworkId = std::nullopt;
        remoteAuthParam->collectorNetworkId = std::nullopt;
        remoteAuthParam->collectorTokenId = std::nullopt;
        if (ipcRemoteAuthParam.isHasVerifierNetworkId) {
            remoteAuthParam->verifierNetworkId = ipcRemoteAuthParam.verifierNetworkId;
        }
        if (ipcRemoteAuthParam.isHasCollectorNetworkId) {
            remoteAuthParam->collectorNetworkId = ipcRemoteAuthParam.collectorNetworkId;
        }
        if (ipcRemoteAuthParam.isHasCollectorTokenId) {
            remoteAuthParam->collectorTokenId = ipcRemoteAuthParam.collectorTokenId;
        }
    }
}

void UserAuthService::InitWidgetParam(const IpcWidgetParamInner &ipcWidgetParam, WidgetParamInner &widgetParam)
{
    widgetParam.title = ipcWidgetParam.title;
    widgetParam.navigationButtonText = ipcWidgetParam.navigationButtonText;
    widgetParam.windowMode = static_cast<WindowModeType>(ipcWidgetParam.windowMode);
    widgetParam.hasContext = ipcWidgetParam.hasContext;
}

int32_t UserAuthService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t UserAuthService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
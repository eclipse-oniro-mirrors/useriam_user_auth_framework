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

#include "user_idm_service.h"

#include "string_ex.h"
#include "accesstoken_kit.h"

#include "context_appstate_observer.h"
#include "context_helper.h"
#include "context_pool.h"
#include "credential_updated_manager.h"
#include "event_listener_manager.h"
#include "hdi_wrapper.h"
#include "iam_callback_proxy.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_defines.h"
#include "iam_time.h"
#include "ipc_common.h"
#include "ipc_skeleton.h"
#include "iam_common_defines.h"
#include "load_mode_handler.h"
#include "nlohmann/json.hpp"
#include "publish_event_adapter.h"
#include "resource_node_pool.h"
#include "resource_node_utils.h"
#include "service_init_manager.h"
#include "system_param_manager.h"
#include "user_idm_database.h"
#include "xcollie_helper.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
REGISTER_SYSTEM_ABILITY_BY_ID(UserIdmService, SUBSYS_USERIAM_SYS_ABILITY_USERIDM, true);
constexpr int32_t USERIAM_IPC_THREAD_NUM = 4;
UserIdmService::UserIdmService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), UserIdmStub(true)
{
}

void UserIdmService::OnStart()
{
    IAM_LOGI("Sa start UserIdmService");
    IPCSkeleton::SetMaxWorkThreadNum(USERIAM_IPC_THREAD_NUM);
    if (!Publish(this)) {
        IAM_LOGE("failed to publish service");
    }
    ServiceInitManager::GetInstance().OnIdmServiceStart();
}

void UserIdmService::OnStop()
{
    IAM_LOGI("Sa stop UserIdmService");
    ServiceInitManager::GetInstance().OnIdmServiceStop();
}

std::string UserIdmService::GetSessionInfoMasked(std::vector<uint8_t> &challenge)
{
    std::ostringstream sessionInfo;
    // Only the first two bytes are processed as the mask result
    constexpr size_t SESSION_INFO_LEN = 2;
    constexpr int32_t UINT8_HEX_WITH = 2;
    size_t bytesToProcess = std::min(challenge.size(), SESSION_INFO_LEN);
    for (size_t i = 0; i < bytesToProcess; i++) {
        // Formatting
        sessionInfo << std::hex << std::setw(UINT8_HEX_WITH) << std::setfill('0');
        sessionInfo << static_cast<uint16_t>(challenge[i]);
    }
    return sessionInfo.str();
}

int32_t UserIdmService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    CancelCurrentEnrollIfExist();

    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return GENERAL_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = hdi->OpenSession(userId, challenge);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("failed to open session, error code:%{public}d", ret);
        return GENERAL_ERROR;
    }

    std::string sessionInfo = GetSessionInfoMasked(challenge);
    IAM_LOGI("set sessionInfo:%{public}s", sessionInfo.c_str());
    SystemParamManager::GetInstance().SetParam(IDM_SESSION_INFO, sessionInfo);
    return SUCCESS;
}

int32_t UserIdmService::CloseSession(int32_t userId)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return GENERAL_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = hdi->CloseSession(userId);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("failed to close session, error code:%{public}d", ret);
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t UserIdmService::GetCredentialInfoInner(int32_t userId, AuthType authType,
    std::vector<CredentialInfo> &credInfoList)
{
    IAM_LOGD("start");
    if (!IpcCommon::CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType, credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
            userId, authType);
        return ret;
    }

    if (credInfos.empty()) {
        IAM_LOGI("no cred enrolled");
        return NOT_ENROLLED;
    }
    for (const auto &credInfo : credInfos) {
        if (credInfo == nullptr) {
            IAM_LOGE("credInfo is nullptr");
            return GENERAL_ERROR;
        }
        CredentialInfo info = {};
        info.credentialId = credInfo->GetCredentialId();
        info.templateId = credInfo->GetTemplateId();
        info.authType = credInfo->GetAuthType();
        info.pinType = credInfo->GetAuthSubType();
        info.isAbandoned = credInfo->GetAbandonFlag();
        info.validityPeriod = credInfo->GetValidPeriod();
        credInfoList.push_back(info);
    }
    return SUCCESS;
}

int32_t UserIdmService::ConvertGetCredentialResult(int32_t resultCode, bool isNotEnrollReturnSuccess)
{
    if (resultCode == SUCCESS) {
        return SUCCESS;
    }
    if (resultCode == NOT_ENROLLED) {
        return isNotEnrollReturnSuccess ? SUCCESS : NOT_ENROLLED;
    }

    IAM_LOGE("GetCredentialInfo fail, resultCode: %{public}d", resultCode);
    if (resultCode == INVALID_PARAMETERS || resultCode == CHECK_PERMISSION_FAILED) {
        return resultCode;
    }
    return GENERAL_ERROR;
}

int32_t UserIdmService::GetCredentialInfoImpl(int32_t userId, int32_t authType,
    const sptr<IIdmGetCredInfoCallback> &callback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    std::vector<IpcCredentialInfo> ipcCredInfoList;
    std::vector<CredentialInfo> credInfoList;
    int32_t ret = GetCredentialInfoInner(userId, static_cast<AuthType>(authType), credInfoList);
    if (ret != SUCCESS) {
        ret = ConvertGetCredentialResult(ret, false);
        credInfoList.clear();
    }

    bool hasAbandonedCredential = false;
    for (auto &iter : credInfoList) {
        if (iter.isAbandoned && iter.validityPeriod == 0) {
            hasAbandonedCredential = true;
            continue;
        }
        IpcCredentialInfo ipcCredInfo;
        ipcCredInfo.authType = static_cast<int32_t>(iter.authType);
        ipcCredInfo.pinType = static_cast<int32_t>(iter.pinType.value_or(PIN_SIX));
        ipcCredInfo.credentialId = iter.credentialId;
        ipcCredInfo.templateId = iter.templateId;
        ipcCredInfo.isAbandoned = iter.isAbandoned;
        ipcCredInfo.validityPeriod = iter.validityPeriod;
        ipcCredInfoList.push_back(ipcCredInfo);
    }

    auto retCode = callback->OnCredentialInfos(ret, ipcCredInfoList);
    if (retCode != SUCCESS) {
        IAM_LOGE("OnCredentialInfos fail, ret: %{public}d", retCode);
    }

    if (hasAbandonedCredential) {
        ClearUnavailableCredential(userId);
    }
    return ret;
}

int32_t UserIdmService::GetCredentialInfo(int32_t userId, int32_t authType,
    const sptr<IIdmGetCredInfoCallback> &callback, int32_t &funcResult)
{
    funcResult = GetCredentialInfoImpl(userId, authType, callback);
    return SUCCESS;
}

int32_t UserIdmService::GetSecInfoInner(int32_t userId, SecUserInfo &secUserInfo)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    std::shared_ptr<SecureUserInfoInterface> userInfos = nullptr;
    int32_t ret = UserIdmDatabase::Instance().GetSecUserInfo(userId, userInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get secUserInfo fail, ret:%{public}d, userId:%{public}d", ret, userId);
        return ret;
    }
    if (userInfos == nullptr) {
        IAM_LOGE("current userid %{public}d is not existed", userId);
        return GENERAL_ERROR;
    }
    std::vector<std::shared_ptr<EnrolledInfoInterface>> enrolledInfos = userInfos->GetEnrolledInfo();
    for (const auto &enrolledInfo : enrolledInfos) {
        if (enrolledInfo == nullptr) {
            IAM_LOGE("enrolledInfo is nullptr");
            return GENERAL_ERROR;
        }
        EnrolledInfo info = {enrolledInfo->GetAuthType(), enrolledInfo->GetEnrolledId()};
        secUserInfo.enrolledInfo.push_back(info);
    }
    secUserInfo.secureUid = userInfos->GetSecUserId();
    return SUCCESS;
}

int32_t UserIdmService::GetSecInfo(int32_t userId, const sptr<IIdmGetSecureUserInfoCallback> &callback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    IpcSecUserInfo ipcSecUserInfo;
    SecUserInfo secUserInfo = {};
    int32_t ret = GetSecInfoInner(userId, secUserInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("GetSecInfoInner fail, ret: %{public}d", ret);
        secUserInfo.secureUid = 0;
        secUserInfo.enrolledInfo.clear();
    }

    for (auto &iter : secUserInfo.enrolledInfo) {
        IpcEnrolledInfo ipcEnrolledInfo;
        ipcEnrolledInfo.authType = static_cast<int32_t>(iter.authType);
        ipcEnrolledInfo.enrolledId = iter.enrolledId;
        ipcSecUserInfo.enrolledInfo.push_back(ipcEnrolledInfo);
    }
    ipcSecUserInfo.secureUid = secUserInfo.secureUid;
    auto retCode = callback->OnSecureUserInfo(ret, ipcSecUserInfo);
    if (retCode != SUCCESS) {
        IAM_LOGE("OnSecureUserInfo fail, ret: %{public}d", retCode);
    }
    return ret;
}

int32_t UserIdmService::StartEnroll(Enrollment::EnrollmentPara &para,
    const std::shared_ptr<ContextCallback> &contextCallback, Attributes &extraInfo, bool needSubscribeAppState)
{
    if (!para.isUpdate && para.authType == PIN && !para.token.empty()) {
        IAM_LOGI("auth type is pin, clear token");
        para.token.clear();
    }

    auto context = ContextFactory::CreateEnrollContext(para, contextCallback, needSubscribeAppState);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    auto cleaner = ContextHelper::Cleaner(context);
    contextCallback->SetCleaner(cleaner);

    if (!context->Start()) {
        IAM_LOGE("failed to start enroll");
        contextCallback->OnResult(context->GetLatestError(), extraInfo);
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

bool UserIdmService::GetNeedSubscribeAppState(std::string jsonText, const char *key)
{
    if (IpcCommon::CheckPermission(*this, USER_AUTH_FROM_BACKGROUND)) {
        IAM_LOGE("check permission success, no need subscribe app state");
        return false;
    }

    if (jsonText.size() == 0) {
        IAM_LOGE("jsonText size is 0, need subscribe app state");
        return true;
    }
    if (!nlohmann::json::accept(jsonText)) {
        IAM_LOGE("the text is not json, need subscribe app state");
        return true;
    }

    auto root = nlohmann::json::parse(jsonText.c_str());
    if (root.is_null() || root.is_discarded()) {
        IAM_LOGE("root is nullptr, need subscribe app state");
        return true;
    }
    if (root.find(key) == root.end() || !(root[key].is_boolean())) {
        IAM_LOGE("%{public}s not found or not boolean", key);
        return true;
    }
    
    bool isEnrollBackGround = false;
    root.at(key).get_to(isEnrollBackGround);
    return !isEnrollBackGround;
}

int32_t UserIdmService::AddCredential(int32_t userId, const IpcCredentialPara &ipcCredentialPara,
    const sptr<IIamCallback> &idmCallback, bool isUpdate)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback,
        isUpdate ? TRACE_UPDATE_CREDENTIAL : TRACE_ADD_CREDENTIAL);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceUserId(userId);
    contextCallback->SetTraceAuthType(static_cast<AuthType>(ipcCredentialPara.authType));
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();
    Enrollment::EnrollmentPara para = {};
    para.authType = static_cast<AuthType>(ipcCredentialPara.authType);
    para.userId = userId;
    para.pinType = static_cast<PinSubType>(ipcCredentialPara.pinType);
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.token = ipcCredentialPara.token;
    para.isUpdate = isUpdate;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.callerName = callerName;
    para.callerType = callerType;
    para.additionalInfo = ipcCredentialPara.additionalInfo;
    bool needSubscribeAppState = GetNeedSubscribeAppState(para.additionalInfo, "isEnrollBackground");
    return StartEnroll(para, contextCallback, extraInfo, needSubscribeAppState);
}

int32_t UserIdmService::UpdateCredential(int32_t userId, const IpcCredentialPara &ipcCredentialPara,
    const sptr<IIamCallback> &idmCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (idmCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId,
        static_cast<AuthType>(ipcCredentialPara.authType), credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d",
            ret, userId, ipcCredentialPara.authType);
        Attributes extraInfo;
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }

    if (credInfos.empty()) {
        IAM_LOGE("current userid %{public}d has no credential for type %{public}u",
            userId, ipcCredentialPara.authType);
        Attributes extraInfo;
        idmCallback->OnResult(NOT_ENROLLED, extraInfo.Serialize());
        return SUCCESS;
    }

    return AddCredential(userId, ipcCredentialPara, idmCallback, true);
}

int32_t UserIdmService::Cancel(int32_t userId)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t tokenId = IpcCommon::GetAccessTokenId(*this);
    auto contextList = ContextPool::Instance().Select(CONTEXT_ENROLL);
    int32_t ret = GENERAL_ERROR;
    for (const auto &context : contextList) {
        if (auto ctx = context.lock(); ctx != nullptr && tokenId == ctx->GetTokenId()) {
            if (!ctx->Stop()) {
                IAM_LOGE("failed stop %{public}s", GET_MASKED_STRING(ctx->GetContextId()).c_str());
                ret = ctx->GetLatestError();
            }
        }
    }
    return ret;
}

void UserIdmService::CancelCurrentEnrollIfExist()
{
    IAM_LOGD("start");
    auto contextList = ContextPool::Instance().Select(CONTEXT_ENROLL);
    for (const auto &context : contextList) {
        if (auto ctx = context.lock(); ctx != nullptr) {
            IAM_LOGI("stop the old context %{public}s", GET_MASKED_STRING(ctx->GetContextId()).c_str());
            ctx->Stop();
        }
    }
}

int32_t UserIdmService::EnforceDelUser(int32_t userId, const sptr<IIamCallback> &idmCallback)
{
    HILOG_COMM_INFO("user idm service to delete userid: %{public}d", userId);
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback, TRACE_ENFORCE_DELETE_USER);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceUserId(userId);

    if (!IpcCommon::CheckPermission(*this, ENFORCE_USER_IDM)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();
    std::shared_ptr<SecureUserInfoInterface> userInfo = nullptr;
    int32_t ret = UserIdmDatabase::Instance().GetSecUserInfo(userId, userInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("get secUserInfo fail, ret:%{public}d, userId:%{public}d", ret, userId);
        contextCallback->OnResult(ret, extraInfo);
        return ret;
    }
    if (userInfo == nullptr) {
        HILOG_COMM_ERROR("current userid %{public}d is not existed", userId);
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    CredChangeEventInfo changeInfo = {callerName, callerType, 0, 0, false};
    ret = EnforceDelUserInner(userId, contextCallback, "EnforceDeleteUser", changeInfo);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("failed to enforce delete user, ret: %{public}d", ret);
        static_cast<void>(extraInfo.SetUint64Value(Attributes::ATTR_CREDENTIAL_ID, 0));
        contextCallback->OnResult(ret, extraInfo);
        return ret;
    }

    IAM_LOGI("delete user success");
    contextCallback->OnResult(SUCCESS, extraInfo);
    return SUCCESS;
}

void UserIdmService::PostProcessForDelete(int32_t userId,
    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos,
    std::string changeReasonTrace, CredChangeEventType eventType, CredChangeEventInfo &changeInfo)
{
    int32_t ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos, changeReasonTrace);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, err:%{public}d", ret);
    }

    PublishEventAdapter::GetInstance().PublishDeletedEvent(userId);
    bool isExistPin = false;
    for (auto cred : credInfos) {
        if (cred->GetAuthType() == PIN && cred->GetAbandonFlag()) {
            continue;
        }
        if (cred->GetAuthType() == PIN) {
            isExistPin = true;
        }
        changeInfo.lastCredentialId = cred->GetCredentialId();
        CredChangeEventListenerManager::GetInstance().OnNotifyCredChangeEvent(
            userId, cred->GetAuthType(), eventType, changeInfo);
    }
    if (isExistPin) {
        CredentialUpdatedManager::GetInstance().ProcessUserDeleted(userId);
    }
}

int32_t UserIdmService::DelUser(int32_t userId, const std::vector<uint8_t> &authToken,
    const sptr<IIamCallback> &idmCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    HILOG_COMM_INFO("del user, userId: %{public}d", userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback, TRACE_DELETE_USER);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceUserId(userId);

    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();

    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    std::vector<uint8_t> rootSecret;
    int32_t ret = UserIdmDatabase::Instance().DeleteUser(userId, authToken, credInfos, rootSecret);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("failed to delete user, userId: %{pblic}d", userId);
        contextCallback->OnResult(ret, extraInfo);
        return ret;
    }
    if (!extraInfo.SetUint8ArrayValue(Attributes::ATTR_OLD_ROOT_SECRET, rootSecret)) {
        IAM_LOGE("set rootsecret to extraInfo failed");
        contextCallback->OnResult(ret, extraInfo);
        return ret;
    }
    SetAuthTypeTrace(credInfos, contextCallback);
    contextCallback->OnResult(ret, extraInfo);
    CredChangeEventInfo changeInfo = {callerName, callerType, 0, 0, false};
    PostProcessForDelete(userId, credInfos, "DeleteUser", DEL_USER, changeInfo);
    return SUCCESS;
}

int32_t UserIdmService::StartDelete(Deletion::DeleteParam &para,
    const std::shared_ptr<ContextCallback> &contextCallback, Attributes &extraInfo)
{
    HILOG_COMM_INFO("user idm delete, userId: %{public}d, credentialId: %{public}s", para.userId,
        Common::GetMaskedString(para.credentialId).c_str());
    auto context = ContextFactory::CreateDeleteContext(para, contextCallback);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    auto cleaner = ContextHelper::Cleaner(context);
    contextCallback->SetCleaner(cleaner);

    if (!context->Start()) {
        HILOG_COMM_ERROR("failed to start context delete");
        contextCallback->OnResult(context->GetLatestError(), extraInfo);
        return context->GetLatestError();
    }
    return SUCCESS;
}

int32_t UserIdmService::DelCredential(int32_t userId, uint64_t credentialId,
    const std::vector<uint8_t> &authToken, const sptr<IIamCallback> &idmCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback, TRACE_DELETE_CREDENTIAL);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceUserId(userId);

    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();
    std::shared_ptr<CredentialInfoInterface> credInfo;
    Deletion::DeleteParam deleteParam = {
        .userId = userId,
        .credentialId = credentialId,
        .tokenId = IpcCommon::GetAccessTokenId(*this),
        .callerName = callerName,
        .callerType = callerType,
        .token = authToken,
    };
    return StartDelete(deleteParam, contextCallback, extraInfo);
}

int UserIdmService::Dump(int fd, const std::vector<std::u16string> &args)
{
    IAM_LOGI("start");
    if (fd < 0) {
        IAM_LOGE("invalid parameters");
        return INVALID_PARAMETERS;
    }
    std::string arg0 = (args.empty() ? "" : Str16ToStr8(args[0]));
    if (arg0.empty() || arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "      -h: command help.\n");
        dprintf(fd, "      -l: active user info dump.\n");
        return SUCCESS;
    }
    if (arg0.compare("-l") != 0) {
        IAM_LOGE("invalid option");
        dprintf(fd, "Invalid option\n");
        return GENERAL_ERROR;
    }

    std::optional<int32_t> activeUserId;
    if (IpcCommon::GetActiveUserId(activeUserId) != SUCCESS) {
        dprintf(fd, "Internal error.\n");
        IAM_LOGE("failed to get active id");
        return GENERAL_ERROR;
    }
    dprintf(fd, "Active user is %d\n", activeUserId.value());
    std::shared_ptr<SecureUserInfoInterface> userInfo = nullptr;
    int32_t ret = UserIdmDatabase::Instance().GetSecUserInfo(activeUserId.value(), userInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("get secUserInfo fail, ret:%{public}d, userId:%{public}d", ret, activeUserId.value());
        return GENERAL_ERROR;
    }
    if (userInfo == nullptr) {
        IAM_LOGE("userInfo is null");
        return SUCCESS;
    }
    auto enrolledInfo = userInfo->GetEnrolledInfo();
    for (auto &info : enrolledInfo) {
        if (info != nullptr) {
            dprintf(fd, "AuthType %s is enrolled.\n", Common::AuthTypeToStr(info->GetAuthType()));
        }
    }
    return SUCCESS;
}

void UserIdmService::SetAuthTypeTrace(const std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos,
    const std::shared_ptr<ContextCallback> &contextCallback)
{
    uint32_t authTypeTrace = 0;
    for (const auto &credInfo : credInfos) {
        if (credInfo == nullptr) {
            IAM_LOGE("credInfo is nullptr");
            continue;
        }
        authTypeTrace |= static_cast<uint32_t>(credInfo->GetAuthType());
    }
    contextCallback->SetTraceAuthType(static_cast<int32_t>(authTypeTrace));
}

int32_t UserIdmService::EnforceDelUserInner(int32_t userId, std::shared_ptr<ContextCallback> callbackForTrace,
    std::string changeReasonTrace, CredChangeEventInfo &changeInfo)
{
    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().DeleteUserEnforce(userId, credInfos);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("failed to enforce delete user, ret:%{public}d, userId: %{public}d",
            ret, userId);
        return ret;
    }
    SetAuthTypeTrace(credInfos, callbackForTrace);
    PostProcessForDelete(userId, credInfos, changeReasonTrace, ENFORCE_DEL_USER, changeInfo);
    return SUCCESS;
}

int32_t UserIdmService::ClearRedundancyCredentialInner(const std::string &callerName, int32_t callerType)
{
    IAM_LOGI("start");
    std::vector<int32_t> accountInfo;
    int32_t ret = IpcCommon::GetAllUserId(accountInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("GetAllUserId failed");
        return IPC_ERROR;
    }

    std::vector<std::shared_ptr<UserInfoInterface>> userInfos;
    ret = UserIdmDatabase::Instance().GetAllExtUserInfo(userInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("GetAllExtUserInfo failed");
        return INVALID_HDI_INTERFACE;
    }

    if (userInfos.empty()) {
        IAM_LOGE("no userInfo");
        return SUCCESS;
    }

    for (const auto &iter : userInfos) {
        int32_t userId = iter->GetUserId();
        auto callbackForTrace = ContextCallback::NewDummyInstance(TRACE_DELETE_REDUNDANCY);
        if (callbackForTrace == nullptr) {
            IAM_LOGE("failed to get callbackForTrace");
            continue;
        }
        callbackForTrace->SetTraceUserId(userId);
        callbackForTrace->SetTraceCallerName(callerName);
        callbackForTrace->SetTraceCallerType(callerType);
        std::vector<int32_t>::iterator it = std::find(accountInfo.begin(), accountInfo.end(), userId);
        if (it == accountInfo.end()) {
            CredChangeEventInfo changeInfo = {callerName, callerType, 0, 0, false};
            ret = EnforceDelUserInner(userId, callbackForTrace, "DeleteRedundancy", changeInfo);
            Attributes extraInfo;
            callbackForTrace->OnResult(ret, extraInfo);
            IAM_LOGE("ClearRedundancytCredential, userId: %{public}d", userId);
        }
    }
    return SUCCESS;
}

int32_t UserIdmService::ClearRedundancyCredential(const sptr<IIamCallback> &idmCallback)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback, TRACE_DELETE_REDUNDANCY);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }

    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);

    if (!IpcCommon::CheckPermission(*this, CLEAR_REDUNDANCY_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();

    int32_t ret = ClearRedundancyCredentialInner(callerName, callerType);
    if (ret != SUCCESS) {
        HILOG_COMM_ERROR("clear redundancy cred fail, ret:%{public}d, callerName: %{public}s,"
            " callerType: %{public}d", ret, callerName.c_str(), callerType);
    }
    contextCallback->OnResult(ret, extraInfo);
    return ret;
}

int32_t UserIdmService::GetCredentialInfoSync(int32_t userId, int32_t authType,
    std::vector<IpcCredentialInfo> &ipcCredentialInfoList)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    std::vector<CredentialInfo> credentialInfoList;
    int32_t ret = GetCredentialInfoInner(userId, static_cast<AuthType>(authType), credentialInfoList);
    if (ret != SUCCESS) {
        ret = ConvertGetCredentialResult(ret, true);
        credentialInfoList.clear();
    }

    bool hasAbandonedCredential = false;
    for (auto &iter : credentialInfoList) {
        if (iter.isAbandoned && iter.validityPeriod == 0) {
            hasAbandonedCredential = true;
            continue;
        }
        IpcCredentialInfo ipcCredInfo;
        ipcCredInfo.authType = static_cast<int32_t>(iter.authType);
        ipcCredInfo.pinType = static_cast<int32_t>(iter.pinType.value_or(PIN_SIX));
        ipcCredInfo.credentialId = iter.credentialId;
        ipcCredInfo.templateId = iter.templateId;
        ipcCredInfo.isAbandoned = iter.isAbandoned;
        ipcCredInfo.validityPeriod = iter.validityPeriod;
        ipcCredentialInfoList.push_back(ipcCredInfo);
    }

    if (hasAbandonedCredential) {
        ClearUnavailableCredential(userId);
    }
    IAM_LOGI("GetCredentialInfoSync success, credential num:%{public}zu", ipcCredentialInfoList.size());
    return ret;
}

int32_t UserIdmService::RegistCredChangeEventListener(const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    if (!IpcCommon::CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    int32_t result = CredChangeEventListenerManager::GetInstance().RegistEventListener(listener);
    if (result != SUCCESS) {
        IAM_LOGE("failed to regist cred change event listener");
        return result;
    }

    return SUCCESS;
}

int32_t UserIdmService::UnRegistCredChangeEventListener(const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    if (!IpcCommon::CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    int32_t result = CredChangeEventListenerManager::GetInstance().UnRegistEventListener(listener);
    if (result != SUCCESS) {
        IAM_LOGE("failed to unregist cred change event listener");
        return result;
    }
    return SUCCESS;
}

void UserIdmService::ClearUnavailableCredential(int32_t userId)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);

    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().ClearUnavailableCredential(userId, credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("clear expired credential fail, ret:%{public}d, userId:%{public}d", ret, userId);
        return;
    }

    if (credInfos.empty()) {
        IAM_LOGI("no abandoned credential");
        return;
    }

    ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos, "ClearExpiredTemplate");
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
    }

    return;
}

int32_t UserIdmService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t UserIdmService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
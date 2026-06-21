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
#include "simple_auth_context.h"

#include <set>
#include <vector>

#include "auth_common.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "publish_event_adapter.h"
#include "resource_node.h"
#include "resource_node_utils.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"
#include "thread_handler_manager.h"
#include "user_idm_database.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::optional<std::vector<uint64_t>> SimpleAuthContext::GetPropertyTemplateIds(
    Authentication::AuthResultInfo &resultInfo)
{
    IAM_LOGI("start");
    auto scheduleList = GetScheduleList();
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList.size() == 1, std::nullopt);
    auto scheduleNode = scheduleList[0];
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleNode != nullptr, std::nullopt);
    if (scheduleNode->GetAuthType() != PRIVATE_PIN) {
        return scheduleNode->GetTemplateIdList();
    }

    std::vector<uint64_t> templateIds;
    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(resultInfo.userId, scheduleNode->GetAuthType(),
        credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
            resultInfo.userId, scheduleNode->GetAuthType());
        return std::nullopt;
    }

    for (auto &iter : credInfos) {
        if (scheduleNode->GetAuthIntent() == QUESTION_AUTH) {
            if (iter->GetAuthSubType() == PIN_QUESTION) {
                templateIds.push_back(iter->GetTemplateId());
                break;
            }
        } else {
            if (iter->GetAuthSubType() != PIN_QUESTION) {
                templateIds.push_back(iter->GetTemplateId());
                break;
            }
        }
    }

    return templateIds;
}

ResultCode SimpleAuthContext::GetPropertyForAuthResult(Authentication::AuthResultInfo &resultInfo)
{
    IAM_LOGD("start");
    auto scheduleList = GetScheduleList();
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList.size() == 1, GENERAL_ERROR);
    auto scheduleNode = scheduleList[0];
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleNode != nullptr, GENERAL_ERROR);
    if (scheduleNode->GetAuthType() == PIN) {
        resultInfo.nextFailLockoutDuration = FIRST_LOCKOUT_DURATION_OF_PIN;
    } else {
        resultInfo.nextFailLockoutDuration = FIRST_LOCKOUT_DURATION_EXCEPT_PIN;
    }
    if (resultInfo.result != FAIL && resultInfo.result != LOCKED) {
        IAM_LOGI("no need GetPropertyFromExecutor, nextLockDuration:%{public}d", resultInfo.nextFailLockoutDuration);
        return SUCCESS;
    }

    auto resourceNode = scheduleNode->GetVerifyExecutor().lock();
    IF_FALSE_LOGE_AND_RETURN_VAL(resourceNode != nullptr, GENERAL_ERROR);
    auto optionalTemplateIdList = GetPropertyTemplateIds(resultInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(optionalTemplateIdList.has_value(), GENERAL_ERROR);
    std::vector<uint64_t> templateIdList = optionalTemplateIdList.value();
    std::vector<uint32_t> keys = { Attributes::ATTR_FREEZING_TIME, Attributes::ATTR_REMAIN_TIMES};
    if (scheduleNode->GetAuthType() == PIN) {
        keys.push_back(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION);
    }
    Attributes attr;
    attr.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, keys);
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);

    Attributes values;
    int32_t ret = resourceNode->GetProperty(attr, values);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == SUCCESS, GENERAL_ERROR);

    if (scheduleNode->GetAuthType() == PIN) {
        bool getNextDurationRet = values.GetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION,
            resultInfo.nextFailLockoutDuration);
        IF_FALSE_LOGE_AND_RETURN_VAL(getNextDurationRet == true, GENERAL_ERROR);
    }
    bool getFreezingTimeRet = values.GetInt32Value(Attributes::ATTR_FREEZING_TIME, resultInfo.freezingTime);
    IF_FALSE_LOGE_AND_RETURN_VAL(getFreezingTimeRet == true, GENERAL_ERROR);
    bool getRemainTimesRet = values.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, resultInfo.remainTimes);
    IF_FALSE_LOGE_AND_RETURN_VAL(getRemainTimesRet == true, GENERAL_ERROR);

    IAM_LOGI("success, nextFailLockoutDuration:%{public}d, freezingTime:%{public}d, remainTime:%{public}d",
        resultInfo.nextFailLockoutDuration, resultInfo.freezingTime, resultInfo.remainTimes);
    return SUCCESS;
}

SimpleAuthContext::SimpleAuthContext(uint64_t contextId, std::shared_ptr<Authentication> auth,
    std::shared_ptr<ContextCallback> callback, bool needSubscribeAppState)
    : BaseContext("SimpleAuth", contextId, callback, needSubscribeAppState),
      auth_(auth)
{
}

SimpleAuthContext::SimpleAuthContext(const std::string &type, uint64_t contextId, std::shared_ptr<Authentication> auth,
    std::shared_ptr<ContextCallback> callback)
    : BaseContext(type, contextId, callback, true),
      auth_(auth)
{
}

ContextType SimpleAuthContext::GetContextType() const
{
    return CONTEXT_SIMPLE_AUTH;
}

uint32_t SimpleAuthContext::GetTokenId() const
{
    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, 0);
    return auth_->GetAccessTokenId();
}

int32_t SimpleAuthContext::GetUserId() const
{
    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, INVALID_USER_ID);
    return auth_->GetUserId();
}

int32_t SimpleAuthContext::GetAuthType() const
{
    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, INVALID_AUTH_TYPE);
    return auth_->GetAuthType();
}

std::string SimpleAuthContext::GetCallerName() const
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback_ != nullptr, "");
    return callback_->GetCallerName();
}

bool SimpleAuthContext::OnStart()
{
    IAM_LOGD("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, false);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList = {};
    bool startRet = auth_->Start(scheduleList, shared_from_this());
    if (!startRet) {
        IAM_LOGE("%{public}s auth start fail", GetDescription());
        SetLatestError(auth_->GetLatestError());
        return startRet;
    }
    SetScheduleList(scheduleList);

    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList.size() == 1, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList[0] != nullptr, false);
    bool startScheduleRet = scheduleList[0]->StartSchedule();
    IF_FALSE_LOGE_AND_RETURN_VAL(startScheduleRet, false);
    IAM_LOGI("%{public}s Schedule:%{public}s Type:%{public}d success", GetDescription(),
        GET_MASKED_STRING(scheduleList[0]->GetScheduleId()).c_str(), scheduleList[0]->GetAuthType());
    return true;
}

void SimpleAuthContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    HILOG_COMM_INFO("%{public}s receive result code %{public}d", GetDescription(), resultCode);
    Authentication::AuthResultInfo resultInfo = {};
    bool updateRet = UpdateScheduleResult(scheduleResultAttr, resultInfo);
    IAM_LOGI("update result %{public}d, resultInfo result %{public}d", updateRet, resultInfo.result);
    if (!updateRet) {
        HILOG_COMM_ERROR("%{public}s update schedule result fail, res: %{public}d, resultInfo.result: %{public}d",
            GetDescription(), updateRet, resultInfo.result);
        if (resultCode == SUCCESS) {
            resultCode = GetLatestError();
        }
        resultInfo.result = resultCode;
    } else if (resultCode != resultInfo.result) {
        resultInfo.result = (resultInfo.result == SUCCESS ? resultCode : resultInfo.result);
    }
    if (GetPropertyForAuthResult(resultInfo) != SUCCESS) {
        IAM_LOGE("GetPropertyForAuthResult failed");
    }

    if (resultInfo.result == SUCCESS && GetAuthType() == PIN) {
        PublishEventAdapter::GetInstance().CachePinUpdateParam(resultInfo.reEnrollFlag);
    }
    SendAuthExecutorMsg();
    InvokeResultCallback(resultInfo);
    IAM_LOGI("%{public}s on result %{public}d finish", GetDescription(), resultInfo.result);
}

bool SimpleAuthContext::OnStop()
{
    IAM_LOGI("%{public}s start", GetDescription());
    auto scheduleList = GetScheduleList();
    if (scheduleList.size() == 1 && scheduleList[0] != nullptr) {
        scheduleList[0]->StopSchedule();
    }

    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, false);
    bool cancelRet = auth_->Cancel();
    if (!cancelRet) {
        HILOG_COMM_ERROR("%{public}s auth stop fail", GetDescription());
        SetLatestError(auth_->GetLatestError());
        return cancelRet;
    }
    return true;
}

void SimpleAuthContext::SendAuthExecutorMsg()
{
    IAM_LOGI("begin");
    IF_FALSE_LOGE_AND_RETURN(auth_ != nullptr);
    auto authExecutorMsgs = auth_->GetAuthExecutorMsgs();
    auto &threadManager = ThreadHandlerManager::GetInstance();

    for (uint32_t msgIndex = 0; msgIndex < authExecutorMsgs.size(); msgIndex++) {
        auto authExecutorMsg = authExecutorMsgs[msgIndex];
        threadManager.PostTaskOnTemporaryThread("SendExecutorMsg", [authExecutorMsg]() {
            ResourceNodeUtils::SendMsgToExecutor(
                authExecutorMsg.executorIndex, authExecutorMsg.commandId, authExecutorMsg.msg);
        });
    }
    IAM_LOGI("end");
}

bool SimpleAuthContext::UpdateScheduleResult(const std::shared_ptr<Attributes> &scheduleResultAttr,
    Authentication::AuthResultInfo &resultInfo)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleResultAttr != nullptr, false);
    std::vector<uint8_t> scheduleResult;
    bool getResultCodeRet = scheduleResultAttr->GetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult);
    IF_FALSE_LOGE_AND_RETURN_VAL(getResultCodeRet == true, false);
    bool updateRet = auth_->Update(scheduleResult, resultInfo);
    if (!updateRet) {
        HILOG_COMM_ERROR("%{public}s auth update fail", GetDescription());
        SetLatestError(auth_->GetLatestError());
        return updateRet;
    }
    return true;
}

bool SimpleAuthContext::SetCredentialDigest(const Authentication::AuthResultInfo &resultInfo,
    Attributes &finalResult) const
{
    uint64_t credentialDigest = resultInfo.credentialDigest;
    if (resultInfo.sdkVersion < INNER_API_VERSION_10000) {
        credentialDigest = resultInfo.credentialDigest & UINT16_MAX;
    }
    bool setCredentialDigestRet = finalResult.SetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST,
        credentialDigest);
    IF_FALSE_LOGE_AND_RETURN_VAL(setCredentialDigestRet == true, false);
    bool setCredentialCountRet = finalResult.SetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT,
        resultInfo.credentialCount);
    IF_FALSE_LOGE_AND_RETURN_VAL(setCredentialCountRet == true, false);

    return true;
}

void SimpleAuthContext::InvokeResultCallback(const Authentication::AuthResultInfo &resultInfo) const
{
    HILOG_COMM_INFO("%{public}s invoke result callback, result: %{public}d, reEnrollFlag: %{public}d",
        GetDescription(), resultInfo.result, resultInfo.reEnrollFlag);
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    Attributes finalResult;
    bool setResultCodeRet = finalResult.SetInt32Value(Attributes::ATTR_RESULT_CODE, resultInfo.result);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet == true);
    bool setNextDurationRet = finalResult.SetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION,
        resultInfo.nextFailLockoutDuration);
    IF_FALSE_LOGE_AND_RETURN(setNextDurationRet == true);
    if (resultInfo.result == FAIL || resultInfo.result == LOCKED || resultInfo.result == SUCCESS) {
        bool setFreezingTimeRet = finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, resultInfo.freezingTime);
        IF_FALSE_LOGE_AND_RETURN(setFreezingTimeRet == true);
        bool setRemainTimesRet = finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, resultInfo.remainTimes);
        IF_FALSE_LOGE_AND_RETURN(setRemainTimesRet == true);
    }
    if ((resultInfo.result == SUCCESS || resultInfo.token.size() != 0) && resultInfo.sdkVersion > API_VERSION_9) {
        bool credentialDigest = SetCredentialDigest(resultInfo, finalResult);
        IF_FALSE_LOGE_AND_RETURN(credentialDigest == true);
    }
    if (resultInfo.result == SUCCESS) {
        bool setUserIdRet = finalResult.SetInt32Value(Attributes::ATTR_USER_ID, resultInfo.userId);
        IF_FALSE_LOGE_AND_RETURN(setUserIdRet == true);
        bool setCredentialIdRet = finalResult.SetUint64Value(Attributes::ATTR_CREDENTIAL_ID, resultInfo.credentialId);
        IF_FALSE_LOGE_AND_RETURN(setCredentialIdRet == true);
        IAM_LOGI("matched userId: %{public}d, credentialId: %{public}s.", resultInfo.userId,
            GET_MASKED_STRING(resultInfo.credentialId).c_str());
        bool setExpiredRet = finalResult.SetInt64Value(Attributes::ATTR_PIN_EXPIRED_INFO, resultInfo.pinExpiredInfo);
        IF_FALSE_LOGE_AND_RETURN(setExpiredRet == true);
    }
    if (resultInfo.token.size() != 0) {
        IAM_LOGI("result token size: %{public}zu.", resultInfo.token.size());
        bool setSignatureResult = finalResult.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, resultInfo.token);
        IF_FALSE_LOGE_AND_RETURN(setSignatureResult == true);
    }
    if (resultInfo.rootSecret.size() != 0) {
        bool setRootSecret = finalResult.SetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, resultInfo.rootSecret);
        IF_FALSE_LOGE_AND_RETURN(setRootSecret == true);
    }
    if (resultInfo.remoteAuthResultMsg.size() != 0) {
        bool setRemoteAuthResultMsg = finalResult.SetUint8ArrayValue(Attributes::ATTR_SIGNED_AUTH_RESULT,
            resultInfo.remoteAuthResultMsg);
        IF_FALSE_LOGE_AND_RETURN(setRemoteAuthResultMsg == true);
    }
    bool setReEnrollFlagRet = finalResult.SetBoolValue(Attributes::ATTR_RE_ENROLL_FLAG, resultInfo.reEnrollFlag);
    IF_FALSE_LOGE_AND_RETURN(setReEnrollFlagRet == true);

    callback_->SetTraceAuthFinishReason("SimpleAuthContext InvokeResultCallback");
    callback_->OnResult(resultInfo.result, finalResult);
    IAM_LOGI("%{public}s invoke result callback success, result %{public}d", GetDescription(), resultInfo.result);
}

void SimpleAuthContext::SetRemoteAuthParam(const WidgetParamInner &widgetParam,
    const sptr<IModalCallback> &modalCallback)
{
    static_cast<void>(widgetParam);
    static_cast<void>(modalCallback);
    IAM_LOGE("not implemented");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

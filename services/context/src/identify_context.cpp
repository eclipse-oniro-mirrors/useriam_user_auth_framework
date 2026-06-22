/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "identify_context.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_IDENTIFY_CONTEXT

namespace OHOS {
namespace UserIam {
namespace UserAuth {
IdentifyContext::IdentifyContext(uint64_t contextId, std::shared_ptr<Identification> identify,
    std::shared_ptr<ContextCallback> callback)
    : BaseContext("Identify", contextId, callback, true),
      identify_(identify)
{
}

ContextType IdentifyContext::GetContextType() const
{
    return CONTEXT_IDENTIFY;
}

uint32_t IdentifyContext::GetTokenId() const
{
    IF_FALSE_LOGE_AND_RETURN_VAL(identify_ != nullptr, 0);
    return identify_->GetAccessTokenId();
}

bool IdentifyContext::OnStart()
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(identify_ != nullptr, false);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList = {};
    bool startRet = identify_->Start(scheduleList, shared_from_this());
    if (!startRet) {
        IAM_LOGE("%{public}s identify start fail", GetDescription());
        SetLatestError(identify_->GetLatestError());
        return startRet;
    }
    SetScheduleList(scheduleList);

    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList.size() == 1, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList[0] != nullptr, false);
    bool startScheduleRet = scheduleList[0]->StartSchedule();
    IF_FALSE_LOGE_AND_RETURN_VAL(startScheduleRet, false);
    IAM_LOGI("%{public}s success", GetDescription());
    return true;
}

void IdentifyContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGI("%{public}s receive result code %{public}d", GetDescription(), resultCode);
    Identification::IdentifyResultInfo resultInfo = {};
    bool updateRet = UpdateScheduleResult(scheduleResultAttr, resultInfo);
    if (!updateRet) {
        IAM_LOGE("%{public}s UpdateScheduleResult fail", GetDescription());
        if (resultCode == SUCCESS) {
            resultCode = GetLatestError();
        }
        resultInfo.result = resultCode;
    }
    InvokeResultCallback(resultInfo);
    IAM_LOGI("%{public}s on result %{public}d finish", GetDescription(), resultCode);
}

bool IdentifyContext::OnStop()
{
    IAM_LOGI("%{public}s start", GetDescription());
    auto scheduleList = GetScheduleList();
    if (scheduleList.size() == 1 && scheduleList[0] != nullptr) {
        scheduleList[0]->StopSchedule();
    }

    IF_FALSE_LOGE_AND_RETURN_VAL(identify_ != nullptr, false);
    bool cancelRet = identify_->Cancel();
    if (!cancelRet) {
        IAM_LOGE("%{public}s identify cancel fail", GetDescription());
        SetLatestError(identify_->GetLatestError());
        return cancelRet;
    }
    return true;
}

bool IdentifyContext::UpdateScheduleResult(const std::shared_ptr<Attributes> &scheduleResultAttr,
    Identification::IdentifyResultInfo &resultInfo)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(identify_ != nullptr, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleResultAttr != nullptr, false);
    std::vector<uint8_t> scheduleResult;
    bool getResultCodeRet = scheduleResultAttr->GetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult);
    IF_FALSE_LOGE_AND_RETURN_VAL(getResultCodeRet == true, false);
    bool updateRet = identify_->Update(scheduleResult, resultInfo);
    if (!updateRet) {
        IAM_LOGE("%{public}s identify update fail", GetDescription());
        SetLatestError(identify_->GetLatestError());
        return updateRet;
    }
    return true;
}

void IdentifyContext::InvokeResultCallback(const Identification::IdentifyResultInfo &resultInfo) const
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    Attributes finalResult;
    bool setResultCodeRet = finalResult.SetInt32Value(Attributes::ATTR_RESULT_CODE, resultInfo.result);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet == true);
    bool setUserIdRet = finalResult.SetInt32Value(Attributes::ATTR_USER_ID, resultInfo.userId);
    IF_FALSE_LOGE_AND_RETURN(setUserIdRet == true);
    if (resultInfo.token.size() != 0) {
        bool setSignatureResult = finalResult.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, resultInfo.token);
        IF_FALSE_LOGE_AND_RETURN(setSignatureResult == true);
    }

    callback_->OnResult(resultInfo.result, finalResult);
    IAM_LOGI("%{public}s invoke result callback success", GetDescription());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

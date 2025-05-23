/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "delete_context.h"

#include "hisysevent_adapter.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "resource_node_utils.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
DeleteContext::DeleteContext(uint64_t contextId, std::shared_ptr<Deletion> deletion,
    std::shared_ptr<ContextCallback> callback)
    : BaseContext("Delete", contextId, callback, false), deletion_(deletion)
{
}

ContextType DeleteContext::GetContextType() const
{
    return CONTEXT_DELETE;
}

uint32_t DeleteContext::GetTokenId() const
{
    IF_FALSE_LOGE_AND_RETURN_VAL(deletion_ != nullptr, 0);
    return deletion_->GetAccessTokenId();
}

int32_t DeleteContext::GetUserId() const
{
    IF_FALSE_LOGE_AND_RETURN_VAL(deletion_ != nullptr, INVALID_USER_ID);
    return deletion_->GetUserId();
}

bool DeleteContext::OnStart()
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(deletion_ != nullptr, false);
    bool isCredentilaDelete = false;
    bool startRet = deletion_->Start(scheduleList_, shared_from_this(), isCredentilaDelete);
    if (!startRet) {
        IAM_LOGE("%{public}s delete start fail", GetDescription());
        SetLatestError(deletion_->GetLatestError());
        return startRet;
    }

    if (isCredentilaDelete) {
        InvokeResultCallback(ResultCode::SUCCESS);
    } else {
        IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList_.size() == 1, false);
        IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList_[0] != nullptr, false);
        bool startScheduleRet = scheduleList_[0]->StartSchedule();
        IF_FALSE_LOGE_AND_RETURN_VAL(startScheduleRet, false);
        IAM_LOGI("%{public}s Schedule:%{public}s Type:%{public}d success", GetDescription(),
            GET_MASKED_STRING(scheduleList_[0]->GetScheduleId()).c_str(), scheduleList_[0]->GetAuthType());
    }
    return true;
}

void DeleteContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGI("%{public}s receive result code %{public}d", GetDescription(), resultCode);
    bool updateRet = UpdateScheduleResult(scheduleResultAttr);
    if (!updateRet) {
        IAM_LOGE("%{public}s UpdateScheduleResult fail", GetDescription());
        if (resultCode == SUCCESS) {
            resultCode = GetLatestError();
        }
    }
    InvokeResultCallback(resultCode);
    IAM_LOGI("%{public}s on result %{public}d finish", GetDescription(), resultCode);
}

bool DeleteContext::OnStop()
{
    IAM_LOGI("%{public}s start", GetDescription());
    if (scheduleList_.size() == 1 && scheduleList_[0] != nullptr) {
        scheduleList_[0]->StopSchedule();
    }

    IF_FALSE_LOGE_AND_RETURN_VAL(deletion_ != nullptr, false);
    bool cancelRet = deletion_->Cancel();
    if (!cancelRet) {
        IAM_LOGE("%{public}s delete stop fail", GetDescription());
        SetLatestError(deletion_->GetLatestError());
        return cancelRet;
    }
    return true;
}

bool DeleteContext::UpdateScheduleResult(const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(deletion_ != nullptr, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleResultAttr != nullptr, false);
    std::vector<uint8_t> scheduleResult;
    bool getResultCodeRet = scheduleResultAttr->GetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult);
    IF_FALSE_LOGE_AND_RETURN_VAL(getResultCodeRet, false);
    std::shared_ptr<CredentialInfoInterface> infoToDel;
    bool updateRet = deletion_->Update(scheduleResult, infoToDel);
    if (!updateRet) {
        IAM_LOGE("%{public}s delete update fail", GetDescription());
        SetLatestError(deletion_->GetLatestError());
        return updateRet;
    }
    if (infoToDel == nullptr) {
        IAM_LOGI("no credential to delete");
    } else {
        std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos = {infoToDel};
        int32_t ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos, "DeleteForUpdate");
        if (ret != SUCCESS) {
            IAM_LOGE("failed to notify executor delete template, error code : %{public}d", ret);
        }
    }

    return true;
}

void DeleteContext::InvokeResultCallback(int32_t resultCode) const
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    Attributes finalResult;
    callback_->OnResult(resultCode, finalResult);
    IAM_LOGI("%{public}s invoke result callback success", GetDescription());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

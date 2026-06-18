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

#include "abandon_command.h"

#include "iam_executor_framework_types.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "iam_defines.h"
#include "hisysevent_adapter.h"

#define LOG_FILE_ID LOG_FILE_ABANDON_COMMAND
#define LOG_TAG "USER_AUTH_EXECUTOR"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
AbandonCommand::AbandonCommand(std::weak_ptr<Executor> executor, uint64_t scheduleId,
    const Attributes &attributes, std::shared_ptr<ExecutorMessenger> executorMessenger)
    : AsyncCommandBase("Abandon", scheduleId, executor, executorMessenger),
      attributes_(Common::MakeShared<Attributes>(attributes.Serialize()))
{
}

ResultCode AbandonCommand::SendRequest()
{
    IAM_LOGI("%{public}s send request start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, ResultCode::GENERAL_ERROR);

    auto hdi = GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    uint32_t tokenId = 0;
    bool getTokenIdRet = attributes_->GetUint32Value(Attributes::ATTR_ACCESS_TOKEN_ID, tokenId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTokenIdRet, ResultCode::GENERAL_ERROR);

    std::vector<uint8_t> extraInfo;
    bool getExtraInfoRet = attributes_->GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExtraInfoRet, ResultCode::GENERAL_ERROR);

    int32_t userId;
    bool getUserId = attributes_->GetInt32Value(Attributes::ATTR_USER_ID, userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getUserId, ResultCode::GENERAL_ERROR);

    std::vector<uint64_t> templateIds;
    bool getTempalteIds = attributes_->GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIds);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTempalteIds, ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(templateIds.size() != 0, ResultCode::GENERAL_ERROR);

    ResultCode ret = hdi->Abandon(scheduleId_, (DeleteParam) { tokenId, userId, templateIds[0], extraInfo},
        shared_from_this());
    IAM_LOGI("%{public}s abandon result %{public}d", GetDescription(), ret);
    return ret;
}

void AbandonCommand::OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s on result start", GetDescription());
    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    auto authAttributes = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN(authAttributes != nullptr);
    bool setResultCodeRet = authAttributes->SetUint32Value(Attributes::ATTR_RESULT_CODE, result);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet == true);
    bool setAuthResultRet =
        authAttributes->SetUint8ArrayValue(Attributes::ATTR_RESULT, nonConstExtraInfo);
    IF_FALSE_LOGE_AND_RETURN(setAuthResultRet == true);
    int32_t ret = MessengerFinish(scheduleId_, result, authAttributes);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("%{public}s call finish fail", GetDescription());
        return;
    }
    IAM_LOGI("%{public}s call finish success result %{public}d", GetDescription(), result);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

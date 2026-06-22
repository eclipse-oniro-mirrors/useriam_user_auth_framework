/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "collect_command.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_executor_framework_types.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_COLLECT_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_COLLECT_COMMAND

namespace OHOS {
namespace UserIam {
namespace UserAuth {
CollectCommand::CollectCommand(std::weak_ptr<Executor> executor, uint64_t scheduleId,
    const Attributes &attributes, std::shared_ptr<ExecutorMessenger> executorMessenger)
    : AsyncCommandBase("COLLECT", scheduleId, executor, executorMessenger),
      attributes_(Common::MakeShared<Attributes>(attributes.Serialize())),
      iamHitraceHelper_(Common::MakeShared<IamHitraceHelper>("CollectCommand"))
{
}

ResultCode CollectCommand::SendRequest()
{
    IAM_LOGD("%{public}s send request start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, ResultCode::GENERAL_ERROR);

    auto hdi = GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    uint32_t collectorTokenId = 0;
    bool getCollectorTokenIdRet = attributes_->GetUint32Value(Attributes::ATTR_COLLECTOR_TOKEN_ID, collectorTokenId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getCollectorTokenIdRet == true, ResultCode::GENERAL_ERROR);
    std::vector<uint8_t> extraInfo;
    bool getExtraInfoRet = attributes_->GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExtraInfoRet == true, ResultCode::GENERAL_ERROR);
    IAM_LOGD("%{public}s collect message len %{public}zu", GetDescription(), extraInfo.size());

    IamHitraceHelper traceHelper("hdi collect");
    ResultCode ret = hdi->Collect(scheduleId_, (CollectParam) { 0, collectorTokenId, extraInfo }, shared_from_this());
    IAM_LOGD("%{public}s collect result %{public}d", GetDescription(), ret);
    return ret;
}

void CollectCommand::OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGD("%{public}s on result start", GetDescription());

    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    auto authAttributes = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN(authAttributes != nullptr);
    bool setResultCodeRet = authAttributes->SetUint32Value(Attributes::ATTR_RESULT_CODE, result);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet == true);
    bool setCollectResultRet =
        authAttributes->SetUint8ArrayValue(Attributes::ATTR_RESULT, nonConstExtraInfo);
    IF_FALSE_LOGE_AND_RETURN(setCollectResultRet == true);
    iamHitraceHelper_ = nullptr;
    int32_t ret = MessengerFinish(scheduleId_, result, authAttributes);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("%{public}s call finish fail", GetDescription());
        return;
    }
    IAM_LOGD("%{public}s call finish success result %{public}d", GetDescription(), result);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

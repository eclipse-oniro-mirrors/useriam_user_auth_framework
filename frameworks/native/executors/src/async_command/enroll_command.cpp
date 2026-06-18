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

#include "enroll_command.h"

#include "iam_executor_framework_types.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "iam_defines.h"
#include "hisysevent_adapter.h"

#define LOG_FILE_ID LOG_FILE_ENROLL_COMMAND
#define LOG_TAG "USER_AUTH_EXECUTOR"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
EnrollCommand::EnrollCommand(std::weak_ptr<Executor> executor, uint64_t scheduleId,
    const Attributes &attributes, std::shared_ptr<ExecutorMessenger> executorMessenger)
    : AsyncCommandBase("ENROLL", scheduleId, executor, executorMessenger),
      attributes_(Common::MakeShared<Attributes>(attributes.Serialize())),
      iamHitraceHelper_(Common::MakeShared<IamHitraceHelper>("EnrollCommand"))
{
}

ResultCode EnrollCommand::SendRequest()
{
    IAM_LOGD("%{public}s send request start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, ResultCode::GENERAL_ERROR);

    auto hdi = GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    uint32_t tokenId = 0;
    bool getTokenIdRet = attributes_->GetUint32Value(Attributes::ATTR_ACCESS_TOKEN_ID, tokenId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTokenIdRet == true, ResultCode::GENERAL_ERROR);

    std::vector<uint8_t> extraInfo;
    bool getExtraInfoRet = attributes_->GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExtraInfoRet == true, ResultCode::GENERAL_ERROR);

    int32_t userId;
    bool getUserId = attributes_->GetInt32Value(Attributes::ATTR_USER_ID, userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getUserId == true, ResultCode::GENERAL_ERROR);

    std::string additionalInfo;
    attributes_->GetStringValue(Attributes::ATTR_ADDITIONAL_INFO, additionalInfo);

    IamHitraceHelper traceHelper("hdi Enroll");
    ResultCode ret = hdi->Enroll(scheduleId_, (EnrollParam) { tokenId, extraInfo, userId, additionalInfo },
        shared_from_this());
    IAM_LOGI("%{public}s enroll result %{public}d", GetDescription(), ret);
    return ret;
}

void EnrollCommand::OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGD("%{public}s on result start", GetDescription());
    TemplateChangeTrace info = {};
    info.scheduleId = scheduleId_;
    info.executorType = GetAuthType();
    info.changeType = TRACE_ADD_CREDENTIAL;
    info.reason = "AddTemplate";
    UserIam::UserAuth::ReportSecurityTemplateChange(info);
    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    auto authAttributes = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN(authAttributes != nullptr);
    bool setResultCodeRet = authAttributes->SetUint32Value(Attributes::ATTR_RESULT_CODE, result);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet == true);
    bool setAuthResultRet =
        authAttributes->SetUint8ArrayValue(Attributes::ATTR_RESULT, nonConstExtraInfo);
    IF_FALSE_LOGE_AND_RETURN(setAuthResultRet == true);
    iamHitraceHelper_ = nullptr;
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

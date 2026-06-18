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

#include "custom_command.h"

#include <chrono>
#include <cstdint>
#include <future>
#include <string>

#include "refbase.h"

#include "iam_executor_framework_types.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_executor_iauth_executor_hdi.h"

#define LOG_FILE_ID LOG_FILE_CUSTOM_COMMAND
#define LOG_TAG "USER_AUTH_EXECUTOR"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
CustomCommand::CustomCommand(std::weak_ptr<Executor> executor, const Attributes &attributes)
    : AsyncCommandBase("CUSTOM", 0, executor, nullptr),
      attributes_(Common::MakeShared<Attributes>(attributes.Serialize()))
{
}

ResultCode CustomCommand::SendRequest()
{
    IAM_LOGD("%{public}s send request start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, ResultCode::GENERAL_ERROR);

    auto hdi = GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    future_ = promise_.get_future();
    uint32_t commandId = 0;
    bool getAuthPropertyModeRet = attributes_->GetUint32Value(Attributes::ATTR_PROPERTY_MODE, commandId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthPropertyModeRet == true, ResultCode::GENERAL_ERROR);

    std::vector<uint8_t> extraInfo;
    bool getExtraInfoRet = attributes_->GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExtraInfoRet == true, ResultCode::GENERAL_ERROR);

    ResultCode ret = hdi->SendCommand(static_cast<UserAuth::PropertyMode>(commandId), extraInfo, shared_from_this());
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s send command result fail ret = %{public}d", GetDescription(), ret);
        OnResult(ret);
        return ret;
    }

    IAM_LOGD("%{public}s send command result success", GetDescription());
    return ResultCode::SUCCESS;
}

void CustomCommand::OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGD("%{public}s on result start", GetDescription());
    SetResult(result);
}

void CustomCommand::OnAcquireInfoInner(int32_t acquire, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGE("%{public}s not support", GetDescription());
}

void CustomCommand::OnMessageInner(int destRole, const std::vector<uint8_t> &msg)
{
    IAM_LOGE("%{public}s not support", GetDescription());
}

ResultCode CustomCommand::GetResult()
{
    if (!future_.valid()) {
        IAM_LOGE("%{public}s get result before request send, error", GetDescription());
        return ResultCode::GENERAL_ERROR;
    }
    IAM_LOGD("%{public}s begin wait future", GetDescription());
    static const std::chrono::seconds maxWaitTime(1);
    auto ret = future_.wait_for(maxWaitTime);
    if (ret != std::future_status::ready) {
        IAM_LOGE("%{public}s future timeout", GetDescription());
        return ResultCode::TIMEOUT;
    }
    IAM_LOGD("%{public}s get result %{public}d", GetDescription(), result_);
    return result_;
}

void CustomCommand::SetResult(ResultCode resultCode)
{
    result_ = resultCode;
    promise_.set_value();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

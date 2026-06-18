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
#include "identification_impl.h"

#include "hdi_wrapper.h"
#include "iam_hitrace_helper.h"
#include "iam_logger.h"
#include "schedule_node_helper.h"

#define LOG_FILE_ID LOG_FILE_IDENTIFICATION_IMPL
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
IdentificationImpl::IdentificationImpl(uint64_t contextId, AuthType authType)
    : contextId_(contextId),
      authType_(authType)
{
}

IdentificationImpl::~IdentificationImpl()
{
    Cancel();
}

void IdentificationImpl::SetLatestError(int32_t error)
{
    if (error != ResultCode::SUCCESS) {
        latestError_ = error;
    }
}

int32_t IdentificationImpl::GetLatestError() const
{
    return latestError_;
}

void IdentificationImpl::SetExecutor(uint32_t executorIndex)
{
    executorIndex_ = executorIndex;
}

void IdentificationImpl::SetChallenge(const std::vector<uint8_t> &challenge)
{
    challenge_ = challenge;
}

void IdentificationImpl::SetAccessTokenId(uint32_t tokenId)
{
    tokenId_ = tokenId;
}

uint32_t IdentificationImpl::GetAccessTokenId() const
{
    return tokenId_;
}

bool IdentificationImpl::Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
    std::shared_ptr<ScheduleNodeCallback> callback)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    HdiScheduleInfo info;
    IamHitraceHelper traceHelper("hdi BeginIdentification");
    auto result =
        hdi->BeginIdentification(contextId_, static_cast<HdiAuthType>(authType_), challenge_, executorIndex_, info);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi BeginAuthentication failed, err is %{public}d", result);
        SetLatestError(result);
        return false;
    }

    std::vector<HdiScheduleInfo> infos = {};
    infos.emplace_back(info);

    ScheduleNodeHelper::NodeOptionalPara para;
    para.tokenId = tokenId_;

    if (!ScheduleNodeHelper::BuildFromHdi(infos, callback, scheduleList, para)) {
        IAM_LOGE("BuildFromHdi failed");
        return false;
    }

    running_ = true;
    return true;
}

bool IdentificationImpl::Update(const std::vector<uint8_t> &scheduleResult, IdentifyResultInfo &resultInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    HdiIdentifyResultInfo info;
    auto result = hdi->UpdateIdentificationResult(contextId_, scheduleResult, info);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi UpdateAuthenticationResult failed, err is %{public}d", result);
        SetLatestError(result);
        return false;
    }

    resultInfo.result = info.result;
    resultInfo.userId = info.userId;
    resultInfo.token = info.token;

    return true;
}

bool IdentificationImpl::Cancel()
{
    if (!running_) {
        return false;
    }
    running_ = false;

    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    auto result = hdi->CancelIdentification(contextId_);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi CancelAuthentication failed, err is %{public}d", result);
        SetLatestError(result);
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
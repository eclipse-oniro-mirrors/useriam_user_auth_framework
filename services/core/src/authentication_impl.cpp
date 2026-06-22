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
#include "authentication_impl.h"

#include "iam_hitrace_helper.h"
#include "iam_logger.h"
#include "schedule_node_helper.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_AUTHENTICATION_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
AuthenticationImpl::AuthenticationImpl(uint64_t contextId, const AuthenticationPara &authPara)
    : contextId_(contextId), authPara_(authPara)
{
}

AuthenticationImpl::~AuthenticationImpl()
{
    Cancel();
}

void AuthenticationImpl::SetLatestError(int32_t error)
{
    if (error != ResultCode::SUCCESS) {
        latestError_ = error;
    }
}

int32_t AuthenticationImpl::GetLatestError() const
{
    return latestError_;
}

void AuthenticationImpl::SetExecutor(uint32_t executorIndex)
{
    executorIndex_ = executorIndex;
}

void AuthenticationImpl::SetChallenge(const std::vector<uint8_t> &challenge)
{
    challenge_ = challenge;
}

void AuthenticationImpl::SetAccessTokenId(uint32_t tokenId)
{
    tokenId_ = tokenId;
}

void AuthenticationImpl::SetEndAfterFirstFail(bool endAfterFirstFail)
{
    endAfterFirstFail_ = endAfterFirstFail;
}

void AuthenticationImpl::SetCollectorUdid(std::string &collectorUdid)
{
    collectorUdid_ = collectorUdid;
}

uint32_t AuthenticationImpl::GetAccessTokenId() const
{
    return tokenId_;
}

int32_t AuthenticationImpl::GetUserId() const
{
    return authPara_.userId;
}

int32_t AuthenticationImpl::GetAuthType() const
{
    return authPara_.authType;
}

std::vector<Authentication::AuthExecutorMsg> AuthenticationImpl::GetAuthExecutorMsgs() const
{
    return authExecutorMsgs_;
}

bool AuthenticationImpl::GetAuthParam(HdiAuthParamExt &param)
{
    HdiCallerType callerType = ConvertATokenTypeToCallerType(authPara_.callerType);
    if (callerType == HDI_CALLER_TYPE_INVALID) {
        IAM_LOGE("ConvertATokenTypeToCallerType failed, ATokenType:%{public}d", authPara_.callerType);
        return false;
    }
    param = {
        .baseParam = {
            .userId = authPara_.userId,
            .authTrustLevel = authPara_.atl,
            .executorSensorHint = executorSensorHint_,
            .challenge = challenge_,
            .callerName = authPara_.callerName,
            .callerType = callerType,
            .apiVersion = authPara_.sdkVersion,
        },
        .authType = authPara_.authType,
        .authIntent = authPara_.authIntent,
        .isOsAccountVerified = authPara_.isOsAccountVerified,
        .collectorUdid = collectorUdid_,
        .credentialIdList = authPara_.credentialIdList,
    };
    return true;
}

bool AuthenticationImpl::Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
    std::shared_ptr<ScheduleNodeCallback> callback)
{
    IAM_LOGI("UserId:%{public}d AuthType:%{public}d ATL:%{public}u authIntent:%{public}d",
        authPara_.userId, authPara_.authType, authPara_.atl, authPara_.authIntent);
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }
    HdiAuthParamExt param = {};
    if (!GetAuthParam(param)) {
        IAM_LOGE("GetAuthParam failed");
        return false;
    }

    std::vector<HdiScheduleInfo> infos;
    IamHitraceHelper traceHelper("hdi BeginAuthentication");
    auto result = hdi->BeginAuthenticationExt(contextId_, param, infos);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi BeginAuthentication failed, err is %{public}d", result);
        SetLatestError(result);
        return false;
    }
    if (infos.empty()) {
        IAM_LOGE("hdi BeginAuthentication failed, infos is empty");
        return false;
    }

    ScheduleNodeHelper::NodeOptionalPara para;
    para.tokenId = tokenId_;
    para.endAfterFirstFail = endAfterFirstFail_;
    para.collectorTokenId = authPara_.collectorTokenId;
    para.authIntent = authPara_.authIntent;
    para.userId = authPara_.userId;
    para.title = authPara_.title;
    para.authScene = authPara_.authScene;

    if (!ScheduleNodeHelper::BuildFromHdi(infos, callback, scheduleList, para)) {
        IAM_LOGE("BuildFromHdi failed");
        return false;
    }

    running_ = true;
    return true;
}

bool AuthenticationImpl::Update(const std::vector<uint8_t> &scheduleResult, AuthResultInfo &resultInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    HdiAuthResultInfo info;
    HdiEnrolledState enrolledState;
    auto result = hdi->UpdateAuthenticationResult(contextId_, scheduleResult, info, enrolledState);
    if (result != HDF_SUCCESS) {
        HILOG_COMM_ERROR("hdi update auth result failed, err is %{public}d", result);
        SetLatestError(result);
    }

    for (auto &[executorIndex, commandId, msg] : info.msgs) {
        Authentication::AuthExecutorMsg authExecutorMsg = {executorIndex, commandId, msg};
        authExecutorMsgs_.emplace_back(authExecutorMsg);
    }

    resultInfo.result = static_cast<decltype(resultInfo.result)>(info.result);
    resultInfo.freezingTime = info.lockoutDuration;
    resultInfo.remainTimes = info.remainAttempts;
    resultInfo.token = info.token;
    resultInfo.rootSecret = info.rootSecret;
    resultInfo.pinExpiredInfo = info.pinExpiredInfo;
    resultInfo.credentialDigest = enrolledState.credentialDigest;
    resultInfo.credentialCount = enrolledState.credentialCount;
    resultInfo.sdkVersion = authPara_.sdkVersion;
    resultInfo.userId = info.userId;
    resultInfo.remoteAuthResultMsg = info.remoteAuthResultMsg;
    resultInfo.credentialId = info.credentialId;
    resultInfo.reEnrollFlag = info.reEnrollFlag;

    if (resultInfo.result != SUCCESS) {
        SetLatestError(resultInfo.result);
    }

    return result == HDF_SUCCESS && resultInfo.result == SUCCESS;
}

bool AuthenticationImpl::Cancel()
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

    auto result = hdi->CancelAuthentication(contextId_);
    if (result != HDF_SUCCESS) {
        HILOG_COMM_ERROR("hdi cancel authentication failed, err is %{public}d", result);
        SetLatestError(result);
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
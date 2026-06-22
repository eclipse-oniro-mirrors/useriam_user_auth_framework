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
#include "enrollment_impl.h"

#include "credential_info_impl.h"
#include "credential_updated_manager.h"
#include "event_listener_manager.h"
#include "hdi_wrapper.h"
#include "iam_hitrace_helper.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "ipc_common.h"
#include "load_mode_handler.h"
#include "publish_event_adapter.h"
#include "schedule_node_helper.h"
#include "update_pin_param_impl.h"
#include "user_idm_database.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_ENROLLMENT_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
EnrollmentImpl::EnrollmentImpl(EnrollmentPara enrollPara) : enrollPara_(enrollPara)
{
}

EnrollmentImpl::~EnrollmentImpl()
{
    Cancel();
}

void EnrollmentImpl::SetLatestError(int32_t error)
{
    if (error != ResultCode::SUCCESS) {
        latestError_ = error;
    }
}

int32_t EnrollmentImpl::GetLatestError() const
{
    return latestError_;
}

void EnrollmentImpl::SetExecutorSensorHint(uint32_t executorSensorHint)
{
    executorSensorHint_ = executorSensorHint;
}

void EnrollmentImpl::SetAuthToken(const std::vector<uint8_t> &authToken)
{
    authToken_ = authToken;
}

void EnrollmentImpl::SetAccessTokenId(uint32_t tokenId)
{
    tokenId_ = tokenId;
}

uint32_t EnrollmentImpl::GetAccessTokenId() const
{
    return tokenId_;
}

void EnrollmentImpl::SetPinSubType(PinSubType pinSubType)
{
    pinSubType_ = pinSubType;
}

void EnrollmentImpl::SetIsUpdate(bool isUpdate)
{
    isUpdate_ = isUpdate;
}

int32_t EnrollmentImpl::GetUserId() const
{
    return enrollPara_.userId;
}

bool EnrollmentImpl::Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
    std::shared_ptr<ScheduleNodeCallback> callback)
{
    IAM_LOGE("UserId:%{public}d, AuthType:%{public}d, pinSubType:%{public}d, additionalInfo:%{public}zu",
        enrollPara_.userId, enrollPara_.authType, enrollPara_.pinType, enrollPara_.additionalInfo.size());
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }
    // cache secUserId first in case of update
    if (isUpdate_ && !GetSecUserId(secUserId_)) {
        IAM_LOGE("get and cache secUserId fail");
        return false;
    }

    HdiScheduleInfo info = {};
    int32_t userType;
    if (IpcCommon::GetUserTypeByUserId(enrollPara_.userId, userType) != SUCCESS) {
        IAM_LOGE("failed to get userType");
        return false;
    }
    HdiCallerType callerType = ConvertATokenTypeToCallerType(enrollPara_.callerType);
    if (callerType == HDI_CALLER_TYPE_INVALID) {
        IAM_LOGE("ConvertATokenTypeToCallerType failed, ATokenType:%{public}d", enrollPara_.callerType);
        return false;
    }
    HdiEnrollParamExt param = {
        .authType = static_cast<HdiAuthType>(enrollPara_.authType),
        .executorSensorHint = executorSensorHint_,
        .callerName = enrollPara_.callerName,
        .callerType = callerType,
        .apiVersion = enrollPara_.sdkVersion,
        .userId = enrollPara_.userId,
        .userType = userType,
        .authSubType = enrollPara_.pinType,
        .additionalInfo = enrollPara_.additionalInfo,
    };
    IamHitraceHelper traceHelper("hdi BeginEnrollment");
    auto result = hdi->BeginEnrollmentExt(authToken_, param, info);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi BeginEnrollment failed, err is %{public}d", result);
        SetLatestError(result);
        return false;
    }

    return StartSchedule(enrollPara_.userId, info, scheduleList, callback);
}

bool EnrollmentImpl::GetSecUserId(std::optional<uint64_t> &secUserId)
{
    secUserId = std::nullopt;
    if (enrollPara_.authType != PIN) {
        IAM_LOGI("no need return sec user id");
        return true;
    }
    std::shared_ptr<SecureUserInfoInterface> userInfo = nullptr;
    int32_t ret = UserIdmDatabase::Instance().GetSecUserInfo(enrollPara_.userId, userInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("get secUserInfo fail, ret:%{public}d, userId:%{public}d", ret, enrollPara_.userId);
        return false;
    }
    if (userInfo != nullptr) {
        secUserId = userInfo->GetSecUserId();
        return true;
    }

    // do not delete users in case of updates
    if (isUpdate_) {
        return false;
    }

    IAM_LOGE("current user id %{public}d get fail", enrollPara_.userId);
    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    if (UserIdmDatabase::Instance().DeleteUserEnforce(enrollPara_.userId, credInfos) != SUCCESS) {
        IAM_LOGE("failed to enforce delete user");
    }
    return false;
}

bool EnrollmentImpl::Update(const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
    std::shared_ptr<CredentialInfoInterface> &info, std::shared_ptr<UpdatePinParamInterface> &pinInfo,
    std::optional<uint64_t> &secUserId)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    HdiEnrollResultInfo resultInfo = {};
    auto result = hdi->UpdateEnrollmentResult(enrollPara_.userId, scheduleResult, resultInfo);
    if (result != HDF_SUCCESS) {
        HILOG_COMM_ERROR("hdi update enroll result failed, err is %{public}d, userId is %{public}d,"
            " credentialId: %{public}s", result, enrollPara_.userId, Common::GetMaskedString(credentialId).c_str());
        SetLatestError(result);
        return false;
    }
    IAM_LOGI("hdi UpdateEnrollmentResult success, userId is %{public}d", enrollPara_.userId);

    credentialId = resultInfo.credentialId;
    pinInfo = Common::MakeShared<UpdatePinParamImpl>(resultInfo.oldInfo.credentialId, resultInfo.oldRootSecret,
        resultInfo.rootSecret, resultInfo.authToken);
    if (pinInfo == nullptr) {
        IAM_LOGE("pinInfo bad alloc");
        return false;
    }

    if (isUpdate_) {
        secUserId = secUserId_;
        info = Common::MakeShared<CredentialInfoImpl>(enrollPara_.userId, resultInfo.oldInfo);
        if (info == nullptr) {
            IAM_LOGE("bad alloc");
            return false;
        }
    } else {
        if (!GetSecUserId(secUserId)) {
            IAM_LOGE("enroll get secUserId fail");
            return false;
        }
        IAM_LOGI("enroll not need to delete old cred");
        info = nullptr;
    }
    CredentialUpdatedManager::GetInstance().ProcessCredentialEnrolled(enrollPara_, resultInfo, isUpdate_, scheduleId_);
    return true;
}

bool EnrollmentImpl::Cancel()
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

    auto result = hdi->CancelEnrollment(enrollPara_.userId);
    if (result != HDF_SUCCESS) {
        HILOG_COMM_ERROR("hdi cancel enrollment failed, err is %{public}d", result);
        SetLatestError(result);
        return false;
    }
    return true;
}

bool EnrollmentImpl::StartSchedule(int32_t userId, HdiScheduleInfo &info,
    std::vector<std::shared_ptr<ScheduleNode>> &scheduleList, std::shared_ptr<ScheduleNodeCallback> callback)
{
    IAM_LOGI("start");
    std::vector<HdiScheduleInfo> infos = {};
    infos.emplace_back(info);

    ScheduleNodeHelper::NodeOptionalPara para;
    para.tokenId = tokenId_;
    para.userId = userId;
    para.additionalInfo = enrollPara_.additionalInfo;

    if (!ScheduleNodeHelper::BuildFromHdi(infos, callback, scheduleList, para)) {
        IAM_LOGE("BuildFromHdi failed");
        return false;
    }
    if (scheduleList.size() == 0 || scheduleList[0] == nullptr) {
        IAM_LOGE("Bad Parameter!");
        return false;
    }

    scheduleId_ = scheduleList[0]->GetScheduleId();
    running_ = true;
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
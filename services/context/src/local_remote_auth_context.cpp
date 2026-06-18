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

#include "local_remote_auth_context.h"

#include "device_manager_util.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "relative_timer.h"

#define LOG_FILE_ID LOG_FILE_LOCAL_REMOTE_AUTH_CONTEXT
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t AUTH_TIME_OUT_MS = 3 * 60 * 1000; // 3min
}

LocalRemoteAuthContext::LocalRemoteAuthContext(uint64_t contextId, std::shared_ptr<Authentication> auth,
    LocalRemoteAuthContextParam &param, std::shared_ptr<ContextCallback> callback)
    : SimpleAuthContext("LocalRemoteAuthContext", contextId, auth, callback),
      collectorNetworkId_(param.collectorNetworkId)
{
}

LocalRemoteAuthContext::~LocalRemoteAuthContext()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (cancelTimerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(cancelTimerId_.value());
    }
    IAM_LOGI("%{public}s destroy", GetDescription());
}

ContextType LocalRemoteAuthContext::GetContextType() const
{
    return LOCAL_REMOTE_AUTH_CONTEXT;
}

bool LocalRemoteAuthContext::OnStart()
{
    std::string collectorUdid;
    bool getCollectorUdidRet = DeviceManagerUtil::GetInstance().GetUdidByNetworkId(collectorNetworkId_, collectorUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getCollectorUdidRet, false);

    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, false);
    auth_->SetCollectorUdid(collectorUdid);

    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        cancelTimerId_ = RelativeTimer::GetInstance().Register(
            [weakThis = weak_from_this(), this]() {
                auto sharedThis = weakThis.lock();
                IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);
                OnTimeOut();
            },
            AUTH_TIME_OUT_MS);
    }

    bool startAuthRet = SimpleAuthContext::OnStart();
    IF_FALSE_LOGE_AND_RETURN_VAL(startAuthRet, false);
    auto scheduleList = GetScheduleList();
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList.size() == 1, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList[0] != nullptr, false);

    IAM_LOGI("%{public}s start local remote auth success, scheduleId:%{public}s", GetDescription(),
        GET_MASKED_STRING(scheduleList[0]->GetScheduleId()).c_str());
    return true;
}

void LocalRemoteAuthContext::OnTimeOut()
{
    IAM_LOGI("%{public}s timeout", GetDescription());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    Attributes attr;
    callback_->SetTraceAuthFinishReason("LocalRemoteAuthContext OnTimeOut");
    callback_->OnResult(ResultCode::TIMEOUT, attr);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

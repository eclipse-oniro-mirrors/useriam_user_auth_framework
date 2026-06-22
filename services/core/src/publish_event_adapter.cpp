/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "publish_event_adapter.h"

#include "common_event_manager.h"
#include "event_listener_manager.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_PUBLISH_EVENT_ADAPTER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const std::string TAG_USERID = "userId";
const std::string TAG_AUTHTYPE = "authType";
const std::string TAG_CREDENTIALCOUNT = "credentialCount";
const std::string TAG_SCHEDULEID = "scheduleId";
const std::string TAG_IS_SILENT_CRED_CHANGE = "isSilentCredChange";
const std::string USER_PIN_CREATED_EVENT = "USER_PIN_CREATED_EVENT";
const std::string USER_PIN_DELETED_EVENT = "USER_PIN_DELETED_EVENT";
const std::string USER_PIN_UPDATED_EVENT = "USER_PIN_UPDATED_EVENT";
const std::string USER_CREDENTIAL_UPDATED_EVENT = "USER_CREDENTIAL_UPDATED_EVENT";
const std::string USERIAM_COMMON_EVENT_PERMISSION = "ohos.permission.USE_USER_IDM";
const std::string USERIAM_COMMON_EVENT_SAMGR_PERMISSION = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";

void PublishEvent(EventFwk::CommonEventData data, const std::string &permission)
{
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({permission});
    publishInfo.SetSticky(false);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo)) {
        IAM_LOGE("PublishCommonEvent failed, eventAction is %{public}s", data.GetWant().GetAction().c_str());
        return;
    }
    IAM_LOGI("PublishCommonEvent succeed, eventAction is %{public}s", data.GetWant().GetAction().c_str());
}
} // namespace

PublishEventAdapter &PublishEventAdapter::GetInstance()
{
    static PublishEventAdapter instance;
    return instance;
}

void PublishEventAdapter::PublishDeletedEvent(int32_t userId)
{
    EventFwk::Want want;
    want.SetAction(USER_PIN_DELETED_EVENT);
    EventFwk::CommonEventData data(want);
    data.SetCode(userId);
    PublishEvent(data, USERIAM_COMMON_EVENT_SAMGR_PERMISSION);
    return;
}

void PublishEventAdapter::PublishCreatedEvent(int32_t userId, uint64_t scheduleId)
{
    if (scheduleId == 0) {
        IAM_LOGE("Bad Parameter!");
        return;
    }
    EventFwk::Want want;
    want.SetAction(USER_PIN_CREATED_EVENT);
    want.SetParam(TAG_SCHEDULEID, std::to_string(scheduleId));
    EventFwk::CommonEventData data(want);
    data.SetCode(userId);
    PublishEvent(data, USERIAM_COMMON_EVENT_SAMGR_PERMISSION);
    return;
}

void PublishEventAdapter::PublishUpdatedEvent(int32_t userId, uint64_t credentialId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (userId != userId_ || credentialId != credChangeEventInfo_.lastCredentialId) {
        IAM_LOGE("Bad Parameter!");
        return;
    }
    CredChangeEventListenerManager::GetInstance().OnNotifyCredChangeEvent(userId, PIN, UPDATE_CRED,
        credChangeEventInfo_);
    EventFwk::Want want;
    want.SetAction(USER_PIN_UPDATED_EVENT);
    want.SetParam(TAG_SCHEDULEID, std::to_string(scheduleId_));
    want.SetParam(TAG_IS_SILENT_CRED_CHANGE, std::to_string(credChangeEventInfo_.isSilentCredChange));
    EventFwk::CommonEventData data(want);
    data.SetCode(userId);
    PublishEvent(data, USERIAM_COMMON_EVENT_SAMGR_PERMISSION);
    ClearPinUpdateCacheInfo();
    return;
}

void PublishEventAdapter::CachePinUpdateParam(int32_t userId, uint64_t scheduleId,
    const CredChangeEventInfo &changeInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    userId_ = userId;
    scheduleId_ = scheduleId;
    credChangeEventInfo_ = changeInfo;
    credChangeEventInfo_.isSilentCredChange = reEnrollFlag_;
}

void PublishEventAdapter::CachePinUpdateParam(bool reEnrollFlag)
{
    std::lock_guard<std::mutex> lock(mutex_);
    reEnrollFlag_ = reEnrollFlag;
}

void PublishEventAdapter::ClearPinUpdateCacheInfo()
{
    credChangeEventInfo_ = {};
    reEnrollFlag_ = false;
}

void PublishEventAdapter::PublishCredentialUpdatedEvent(int32_t userId, int32_t authType, uint32_t credentialCount)
{
    std::lock_guard<std::mutex> lock(mutex_);
    EventFwk::Want want;
    want.SetAction(USER_CREDENTIAL_UPDATED_EVENT);
    want.SetParam(TAG_USERID, std::to_string(userId));
    want.SetParam(TAG_AUTHTYPE, std::to_string(authType));
    want.SetParam(TAG_CREDENTIALCOUNT, std::to_string(credentialCount));
    if (authType == AuthType::PIN) {
        want.SetParam(TAG_IS_SILENT_CRED_CHANGE, std::to_string(credChangeEventInfo_.isSilentCredChange));
    } else {
        want.SetParam(TAG_IS_SILENT_CRED_CHANGE, std::to_string(false));
    }
    EventFwk::CommonEventData data(want);
    data.SetCode(0);
    PublishEvent(data, USERIAM_COMMON_EVENT_PERMISSION);
    IAM_LOGI("PublishCredentialUpdatedEvent, userId: %{public}d, authType: %{public}d, credentialCount: %{public}u",
        userId, authType, credentialCount);
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

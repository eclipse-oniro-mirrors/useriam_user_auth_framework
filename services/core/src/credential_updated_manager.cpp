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

#include "credential_updated_manager.h"

#include "nlohmann/json.hpp"

#include "event_listener_manager.h"
#include "iam_logger.h"
#include "publish_event_adapter.h"
#include "system_param_manager.h"
#include "user_idm_database_impl.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_CREDENTIAL_UPDATED_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const std::string USER_ID_KEY = "userId";
const std::string AUTH_TYPE_KEY = "authType";
const std::string CREDENTIAL_COUNT_KEY = "count";
} // namespace

CredentialUpdatedManager &CredentialUpdatedManager::GetInstance()
{
    static CredentialUpdatedManager instance;
    return instance;
}

void CredentialUpdatedManager::ProcessCredentialDeleted(const Deletion::DeleteParam &deletePara, uint64_t credentialId,
    AuthType authType)
{
    IAM_LOGI("ProcessCredentialDeleted called, userId:%{public}d, authType:%{public}d", deletePara.userId, authType);
    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(deletePara.userId, authType, credentialInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret, deletePara.userId,
            authType);
        return;
    }

    uint32_t credentialCount = credentialInfos.size();
    PublishEventAdapter::GetInstance().PublishCredentialUpdatedEvent(deletePara.userId, authType, credentialCount);
    SaveCredentialUpdatedEvent(deletePara.userId, authType, credentialCount);
    PublishEventAdapter::GetInstance().PublishUpdatedEvent(deletePara.userId, credentialId);
    CredChangeEventInfo changeInfo = {deletePara.callerName, deletePara.callerType, 0, credentialId, false};
    if (authType != PIN) {
        CredChangeEventListenerManager::GetInstance().OnNotifyCredChangeEvent(deletePara.userId, authType, DEL_CRED,
            changeInfo);
    }
}

void CredentialUpdatedManager::ProcessCredentialEnrolled(const Enrollment::EnrollmentPara &enrollPara,
    const HdiEnrollResultInfo &resultInfo, bool isUpdate, uint64_t scheduleId)
{
    IAM_LOGI("ProcessCredentialEnrolled called, userId:%{public}d, authType:%{public}d", enrollPara.userId,
        enrollPara.authType);
    CredChangeEventInfo changeInfo = {enrollPara.callerName, enrollPara.callerType, resultInfo.credentialId, 0, false};
    if (isUpdate && enrollPara.authType == PIN) {
        changeInfo.lastCredentialId = resultInfo.oldInfo.credentialId;
        PublishEventAdapter::GetInstance().CachePinUpdateParam(enrollPara.userId, scheduleId, changeInfo);
        return;
    }

    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos;
    if (UserIdmDatabase::Instance().GetCredentialInfo(enrollPara.userId, enrollPara.authType, credentialInfos) !=
        SUCCESS) {
        IAM_LOGE("get credential fail");
        return;
    }

    uint32_t credentialCount = credentialInfos.size();
    PublishEventAdapter::GetInstance().PublishCredentialUpdatedEvent(enrollPara.userId,
        static_cast<int32_t>(enrollPara.authType), credentialCount);
    SaveCredentialUpdatedEvent(enrollPara.userId, enrollPara.authType, credentialCount);
    if (isUpdate && enrollPara.authType != PIN) {
        changeInfo.lastCredentialId = resultInfo.oldInfo.credentialId;
        CredChangeEventListenerManager::GetInstance().OnNotifyCredChangeEvent(enrollPara.userId, enrollPara.authType,
            UPDATE_CRED, changeInfo);
    } else if (!isUpdate && enrollPara.authType != PIN) {
        CredChangeEventListenerManager::GetInstance().OnNotifyCredChangeEvent(enrollPara.userId, enrollPara.authType,
            ADD_CRED, changeInfo);
    } else {
        PublishEventAdapter::GetInstance().PublishCreatedEvent(enrollPara.userId, scheduleId);
        CredChangeEventListenerManager::GetInstance().OnNotifyCredChangeEvent(enrollPara.userId, enrollPara.authType,
            ADD_CRED, changeInfo);
    }
}

void CredentialUpdatedManager::ProcessUserDeleted(int32_t userId)
{
    IAM_LOGI("ProcessUserDeleted called, userId:%{public}d, authType:%{public}d", userId, PIN);
    PublishEventAdapter::GetInstance().PublishCredentialUpdatedEvent(userId, PIN, 0);
    SaveCredentialUpdatedEvent(userId, PIN, 0);
}

// When publishing the credential updated event, it is necessary to write the event to system parameters.
void CredentialUpdatedManager::SaveCredentialUpdatedEvent(int32_t userId, AuthType authType, uint32_t credentialCount)
{
    IAM_LOGI("save credential updated event, userId:%{public}d, authType:%{public}d, credentialCount:%{public}u",
        userId, authType, credentialCount);
    auto eventJson = nlohmann::json {
        {USER_ID_KEY, userId},
        {AUTH_TYPE_KEY, authType},
        {CREDENTIAL_COUNT_KEY, credentialCount}
    };
    std::string event = eventJson.dump();
    SystemParamManager::GetInstance().SetParam(CREDENTIAL_UPDATED_KEY, event);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

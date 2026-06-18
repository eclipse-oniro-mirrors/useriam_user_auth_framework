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

#include "risk_event_manager.h"

#include "system_ability_definition.h"
#include "system_ability.h"

#include "context_appstate_observer.h"
#include "ipc_common.h"
#include "strong_auth_status_manager.h"
#include "system_ability_listener.h"
#include "resource_node_pool.h"
#include "user_idm_database.h"

#define LOG_FILE_ID LOG_FILE_RISK_EVENT_MANAGER
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
RiskEventManager &RiskEventManager::GetInstance()
{
    static RiskEventManager instance;
    return instance;
}

void RiskEventManager::SetRiskEventPropertyForAuthType(int32_t userId,
    const AuthType authType, EventType event)
{
    IAM_LOGI("start");
    Attributes attributes;
    int32_t getAttrRet = SetAttributes(userId, authType, event, attributes);
    if (getAttrRet != SUCCESS) {
        IAM_LOGE("get attributes fail");
        return;
    }

    std::vector<std::weak_ptr<ResourceNode>> authTypeNodes;
    ResourceNodePool::Instance().GetResourceNodeByTypeAndRole(authType, ALL_IN_ONE, authTypeNodes);
    if (authTypeNodes.size() == 0) {
        IAM_LOGE("authTypeNodes is empty");
        return;
    }

    for (auto &authTypeNode : authTypeNodes) {
        auto resourceNode = authTypeNode.lock();
        if (resourceNode != nullptr) {
            int32_t result = resourceNode->SetProperty(attributes);
            IAM_LOGI("set authType %{public}d property finish, ret:%{public}d", authType, result);
        } else {
            IAM_LOGE("resourceNode already expired");
        }
    }
}

ResultCode RiskEventManager::SetAttributes(int32_t userId, const AuthType authType,
    EventType event, Attributes &attributes)
{
    IAM_LOGI("start");
    if (event != EventType::SCREENLOCK_STRONG_AUTH) {
        IAM_LOGE("unknown event type");
        return GENERAL_ERROR;
    }

    bool setModeRet = attributes.SetUint32Value(Attributes::ATTR_PROPERTY_MODE,
        PropertyMode::PROPERTY_MODE_RISK_EVENT);
    if (!setModeRet) {
        IAM_LOGE("set property mode fail");
        return GENERAL_ERROR;
    }

    std::vector<uint8_t> extraInfo;
    int32_t getExtraInfoRet = GetStrongAuthExtraInfo(userId, authType, extraInfo);
    if (getExtraInfoRet != SUCCESS) {
        IAM_LOGE("getExtraInfoRet fail");
        return GENERAL_ERROR;
    }
    bool setExtraInfoRet = attributes.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    if (!setExtraInfoRet) {
        IAM_LOGE("set extra info fail");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

ResultCode RiskEventManager::GetTemplateIdList(int32_t userId, const AuthType authType,
    std::vector<uint64_t> &templateIds)
{
    IAM_LOGI("start");
    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos;
    int32_t getCredInfoRet = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType,
        credentialInfos);
    if (getCredInfoRet == NOT_ENROLLED) {
        IAM_LOGI("userId:%{public}d, authType:%{public}d not enrolled", userId, authType);
        return NOT_ENROLLED;
    }

    if (getCredInfoRet != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d",
            getCredInfoRet, userId, authType);
        return GENERAL_ERROR;
    }
    for (auto &info : credentialInfos) {
        if (info == nullptr) {
            IAM_LOGE("info is null");
            continue;
        }
        templateIds.push_back(info->GetTemplateId());
    }
    return SUCCESS;
}

ResultCode RiskEventManager::GetStrongAuthExtraInfo(int32_t userId, const AuthType authType,
    std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    std::vector<uint64_t> templateIds;
    ResultCode getTemplateIdsRet = GetTemplateIdList(userId, authType, templateIds);
    if (getTemplateIdsRet != SUCCESS) {
        IAM_LOGE("get template id list fail");
        return GENERAL_ERROR;
    }
    Attributes extraInfoAttr;
    bool setTemplateIdListRet = extraInfoAttr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST,
        templateIds);
    if (!setTemplateIdListRet) {
        IAM_LOGE("set template id list fail");
        return GENERAL_ERROR;
    }

    bool setAuthTypeRet = extraInfoAttr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);
    if (!setAuthTypeRet) {
        IAM_LOGE("set auth type fail");
        return GENERAL_ERROR;
    }
    extraInfo = extraInfoAttr.Serialize();
    return SUCCESS;
}

void RiskEventManager::HandleStrongAuthEvent(int32_t userId)
{
    IAM_LOGI("handle strong auth event for userId:%{public}d", userId);
    bool screenLockState = ContextAppStateObserverManager::GetInstance().IsScreenLocked();
    if (!screenLockState) {
        IAM_LOGI("screen is not locked");
        return;
    }
    SetRiskEventPropertyForAuthType(userId, AuthType::FACE, EventType::SCREENLOCK_STRONG_AUTH);
    SetRiskEventPropertyForAuthType(userId, AuthType::FINGERPRINT, EventType::SCREENLOCK_STRONG_AUTH);
}

void RiskEventManager::SyncRiskEvents()
{
    IAM_LOGI("start");
    std::vector<int32_t> userIdList;
    IpcCommon::GetAllUserId(userIdList);
    for (int32_t &userId : userIdList) {
        bool isScreenLockStrongAuth = StrongAuthStatusManager::Instance().IsScreenLockStrongAuth(userId);
        if (isScreenLockStrongAuth) {
            IAM_LOGI("screenlock in strong auth status for userId:%{public}d", userId);
            HandleStrongAuthEvent(userId);
        }
    }
}

void RiskEventManager::OnScreenLock()
{
    IAM_LOGI("start");
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
    handler->PostTask([]() {
        RiskEventManager::GetInstance().SyncRiskEvents();
    });
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
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

#include "event_listener_manager.h"

#include <sstream>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_EVENT_LISTENER_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using DeathRecipient = IRemoteObject::DeathRecipient;
int32_t EventListenerManager::RegistEventListener(const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int32_t result = AddDeathRecipient(this, listener);
    if (result != SUCCESS) {
        IAM_LOGE("AddDeathRecipient fail");
    }
    return result;
}

int32_t EventListenerManager::UnRegistEventListener(const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int32_t result = RemoveDeathRecipient(listener);
    if (result != SUCCESS) {
        IAM_LOGE("RemoveDeathRecipient fail");
    }
    return result;
}

int32_t EventListenerManager::AddDeathRecipient(EventListenerManager *manager,
    const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    auto obj = listener->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return GENERAL_ERROR;
    }

    auto iter = std::find_if(listenerDeathRecipientMap_.begin(), listenerDeathRecipientMap_.end(),
        FinderMap(obj));
    if (iter != listenerDeathRecipientMap_.end()) {
        IAM_LOGE("deathRecipient is already registed");
        return SUCCESS;
    }

    if (obj->IsProxyObject()) {
        sptr<DeathRecipient> dr(new (std::nothrow) EventListenerDeathRecipient(manager));
        if ((dr == nullptr) || (!obj->AddDeathRecipient(dr))) {
            IAM_LOGE("AddDeathRecipient failed");
            return GENERAL_ERROR;
        }
        listenerDeathRecipientMap_.emplace(listener, dr);
    } else {
        listenerDeathRecipientMap_.emplace(listener, nullptr);
    }

    IAM_LOGI("AddDeathRecipient success, listenerSize:%{public}zu", listenerDeathRecipientMap_.size());
    return SUCCESS;
}

int32_t EventListenerManager::RemoveDeathRecipient(const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    auto obj = listener->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return GENERAL_ERROR;
    }

    auto iter = std::find_if(listenerDeathRecipientMap_.begin(), listenerDeathRecipientMap_.end(),
        FinderMap(obj));
    if (iter == listenerDeathRecipientMap_.end()) {
        IAM_LOGE("deathRecipient is not registed");
        return SUCCESS;
    }

    sptr<DeathRecipient> deathRecipient = iter->second;
    if (deathRecipient != nullptr) {
        obj->RemoveDeathRecipient(deathRecipient);
    }

    listenerDeathRecipientMap_.erase(iter);
    IAM_LOGI("RemoveDeathRecipient success, listenerSize:%{public}zu", listenerDeathRecipientMap_.size());
    return SUCCESS;
}

std::map<sptr<IEventListenerCallback>, sptr<DeathRecipient>> EventListenerManager::GetListenerDeathRecipientMap()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return listenerDeathRecipientMap_;
}

EventListenerManager::EventListenerDeathRecipient::EventListenerDeathRecipient(EventListenerManager *manager)
    : eventListenerManager_(manager) {}

void EventListenerManager::EventListenerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr || eventListenerManager_ == nullptr) {
        IAM_LOGE("remote or manager is nullptr");
        return;
    }

    auto deathRecipientMap = eventListenerManager_->GetListenerDeathRecipientMap();
    for (auto &iter : deathRecipientMap) {
        if (iter.first != nullptr && remote == iter.first->AsObject()) {
            int32_t result = eventListenerManager_->UnRegistEventListener(iter.first);
            if (result != SUCCESS) {
                IAM_LOGE("UnRegistEventListener fail");
                return;
            }
        }
    }
}

AuthEventListenerManager &AuthEventListenerManager::GetInstance()
{
    IAM_LOGI("start");
    static AuthEventListenerManager authEventListenerManager;
    return authEventListenerManager;
}

void AuthEventListenerManager::OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType,
    const AuthSuccessEventInfo &eventInfo)
{
    IAM_LOGI("start");
    auto listenerSetTemp = GetListenerDeathRecipientMap();
    for (auto &iter : listenerSetTemp) {
        if (iter.first != nullptr) {
            iter.first->OnNotifyAuthSuccessEvent(userId, authType,
                {eventInfo.callerName, eventInfo.callerType, eventInfo.isWidgetAuth});
        }
    }
}

CredChangeEventListenerManager &CredChangeEventListenerManager::GetInstance()
{
    IAM_LOGI("start");
    static CredChangeEventListenerManager credChangeEventListenerManager;
    return credChangeEventListenerManager;
}

void CredChangeEventListenerManager::OnNotifyCredChangeEvent(int32_t userId, AuthType authType,
    CredChangeEventType eventType, const CredChangeEventInfo &changeInfo)
{
    IAM_LOGI("start");
    IpcCredChangeEventInfo info = {changeInfo.callerName, changeInfo.callerType, changeInfo.credentialId,
        changeInfo.lastCredentialId, changeInfo.isSilentCredChange};
    auto listenerSetTemp = GetListenerDeathRecipientMap();
    for (auto &iter : listenerSetTemp) {
        if (iter.first != nullptr) {
            iter.first->OnNotifyCredChangeEvent(userId, authType, eventType, info);
        }
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
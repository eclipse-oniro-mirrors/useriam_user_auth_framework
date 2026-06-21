/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "remote_auth_callback_manager.h"
#include <algorithm>
#include <mutex>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
RemoteAuthCallbackManager::RemoteAuthCallbackManager()
{
    IAM_LOGI("init");
}

RemoteAuthCallbackManager &RemoteAuthCallbackManager::GetInstance()
{
    static RemoteAuthCallbackManager remoteAuthCallbackManager;
    return remoteAuthCallbackManager;
}

int32_t RemoteAuthCallbackManager::AddRemoteAuthCallback(uint32_t tokenId,
    const sptr<IRemoteAuthCallback> &remoteAuthCallback, std::string &callerName)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    int32_t result = AddDeathRecipient(this, remoteAuthCallback);
    if (result != SUCCESS) {
        IAM_LOGE("AddDeathRecipient fail");
        return result;
    }
    if (remoteAuthCallback != nullptr && remoteAuthCallback->AsObject() != nullptr) {
        remoteObjectTokenIdMap_[remoteAuthCallback->AsObject()] = tokenId;
    }
    callbacks_[tokenId] = std::make_pair(remoteAuthCallback, callerName);
    return SUCCESS;
}

int32_t RemoteAuthCallbackManager::DelRemoteAuthCallback(uint32_t tokenId)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto iter = callbacks_.find(tokenId);
    if (iter != callbacks_.end()) {
        int32_t result = RemoveDeathRecipient(iter->second.first);
        if (result != SUCCESS) {
            IAM_LOGE("RemoveDeathRecipient fail");
            return result;
        }
        if (iter->second.first != nullptr && iter->second.first->AsObject() != nullptr) {
            remoteObjectTokenIdMap_.erase(iter->second.first->AsObject());
        }
        callbacks_.erase(iter);
    }
    return SUCCESS;
}

sptr<IRemoteAuthCallback> RemoteAuthCallbackManager::GetRemoteAuthCallback(uint32_t tokenId)
{
    IAM_LOGI("start"); 
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto iter = callbacks_.find(tokenId);
    if (iter != callbacks_.end()) {
        return iter->second.first;
    }
    return nullptr;
}

std::string RemoteAuthCallbackManager::GetRemoteAuthCallerName(uint32_t tokenId)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto iter = callbacks_.find(tokenId);
    if (iter != callbacks_.end()) {
        return iter->second.second;
    }
    return "";
}

int32_t RemoteAuthCallbackManager::AddDeathRecipient(RemoteAuthCallbackManager *manager,
    const sptr<IRemoteAuthCallback> &callback)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, GENERAL_ERROR);

    auto obj = callback->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return GENERAL_ERROR;
    }

    auto iter = std::find_if(callbackDeathRecipientMap_.begin(), callbackDeathRecipientMap_.end(),
        FinderMap(obj));
    if (iter != callbackDeathRecipientMap_.end()) {
        IAM_LOGE("deathRecipient is already registed");
        return SUCCESS;
    }

    if (obj->IsProxyObject()) {
        sptr<DeathRecipient> dr(new (std::nothrow) RemoteAuthCallbackDeathRecipient(manager));
        if ((dr == nullptr) || (!obj->AddDeathRecipient(dr))) {
            IAM_LOGE("AddDeathRecipient failed");
            return GENERAL_ERROR;
        }
        callbackDeathRecipientMap_.emplace(callback, dr);
    } else {
        callbackDeathRecipientMap_.emplace(callback, nullptr);
    }

    IAM_LOGI("AddDeathRecipient success, callbackSize:%{public}zu", callbackDeathRecipientMap_.size());
    return SUCCESS;
}

int32_t RemoteAuthCallbackManager::RemoveDeathRecipient(const sptr<IRemoteAuthCallback> &callback)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, GENERAL_ERROR);

    auto obj = callback->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return GENERAL_ERROR;
    }

    auto iter = std::find_if(callbackDeathRecipientMap_.begin(), callbackDeathRecipientMap_.end(),
        FinderMap(obj));
    if (iter == callbackDeathRecipientMap_.end()) {
        IAM_LOGE("deathRecipient is not registed");
        return SUCCESS;
    }

    sptr<DeathRecipient> deathRecipient = iter->second;
    if (deathRecipient != nullptr) {
        obj->RemoveDeathRecipient(deathRecipient);
    }

    callbackDeathRecipientMap_.erase(iter);
    IAM_LOGI("RemoveDeathRecipient success, callbackSize:%{public}zu", callbackDeathRecipientMap_.size());
    return SUCCESS;
}

std::map<sptr<IRemoteAuthCallback>, sptr<DeathRecipient>> RemoteAuthCallbackManager::GetCallbackDeathRecipientMap()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return callbackDeathRecipientMap_;
}

RemoteAuthCallbackManager::RemoteAuthCallbackDeathRecipient::RemoteAuthCallbackDeathRecipient(
    RemoteAuthCallbackManager *manager)
    : remoteAuthCallbckManager_(manager) {}

void RemoteAuthCallbackManager::RemoteAuthCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr || remoteAuthCallbckManager_ == nullptr) {
        IAM_LOGE("remote or manager is nullptr");
        return;
    }

    auto deathRecipientMap = remoteAuthCallbckManager_->GetCallbackDeathRecipientMap();
    for (auto &iter : deathRecipientMap) {
        if (iter.first != nullptr && remote == iter.first->AsObject()) {
            int32_t result = remoteAuthCallbckManager_->DelRemoteAuthCallbackOnRemoteDied(iter.first);
            if (result != SUCCESS) {
                IAM_LOGE("DelRemoteAuthCallbackOnRemoteDied fail");
                return;
            }
        }
    }
}

int32_t RemoteAuthCallbackManager::DelRemoteAuthCallbackOnRemoteDied(const sptr<IRemoteAuthCallback> &callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback == nullptr || callback->AsObject() == nullptr) {
        IAM_LOGE("callback or remote object is nullptr");
        return GENERAL_ERROR;
    }
    auto iter = remoteObjectTokenIdMap_.find(callback->AsObject());
    if (iter == remoteObjectTokenIdMap_.end()) {
        IAM_LOGE("tokenId not found");
        return GENERAL_ERROR;
    }
    uint32_t tokenId = iter->second;
    RemoveDeathRecipient(callback);
    remoteObjectTokenIdMap_.erase(iter);
    callbacks_.erase(tokenId);
    IAM_LOGI("DelRemoteAuthCallbackOnRemoteDied success, tokenId:%{public}u", tokenId);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
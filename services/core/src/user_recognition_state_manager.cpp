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

#include "user_recognition_state_manager_impl.h"

#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "accesstoken_kit.h"
#include "callback_death_recipient.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "thread_handler.h"
#include "user_auth_client_defines.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_USER_RECOGNITION_STATE_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct ManagerStore {
    std::mutex mutex;
    std::shared_ptr<IUserRecognitionStateManager> instance;
};

ManagerStore &GetStore()
{
    static ManagerStore store;
    return store;
}
} // namespace

std::shared_ptr<IUserRecognitionStateManager> CreateUserRecognitionStateManager()
{
    return std::shared_ptr<UserRecognitionStateManager>(new UserRecognitionStateManager());
}

IUserRecognitionStateManager &GetUserRecognitionStateManager()
{
    auto &store = GetStore();
    std::shared_ptr<IUserRecognitionStateManager> manager;
    {
        std::lock_guard<std::mutex> lock(store.mutex);
        if (!store.instance) {
            store.instance = CreateUserRecognitionStateManager();
        }
        manager = store.instance;
    }
    if (manager == nullptr) {
        IAM_LOGE("UserRecognitionStateManager is null, abort");
        std::abort();
    }
    return *manager;
}

void SetUserRecognitionStateManager(std::shared_ptr<IUserRecognitionStateManager> manager)
{
    auto &store = GetStore();
    std::lock_guard<std::mutex> lock(store.mutex);
    store.instance = std::move(manager);
}

int32_t UserRecognitionStateManager::RegisterListener(int32_t callerType,
    const sptr<IUserRecognitionCallback> &listener)
{
    IAM_LOGI("start, callerType:%{public}d", callerType);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    auto obj = listener->AsObject();
    IF_FALSE_LOGE_AND_RETURN_VAL(obj != nullptr, GENERAL_ERROR);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(handler != nullptr, GENERAL_ERROR);

    IpcUserRecognitionResult syncResult {};
    size_t listenerSize = 0;

    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (listenerMap_.find(obj) != listenerMap_.end()) {
            IAM_LOGI("listener is already registered");
            return SUCCESS;
        }

        ListenerEntry entry;
        entry.callback = listener;
        entry.callerType = callerType;
        if (obj->IsProxyObject()) {
            auto cleanup = [weakSelf = weak_from_this(), listener]() {
                auto self = weakSelf.lock();
                if (self != nullptr) {
                    self->UnregisterListener(listener);
                }
            };
            entry.deathRecipient = CallbackDeathRecipient::Register(obj, std::move(cleanup));
            IF_FALSE_LOGE_AND_RETURN_VAL(entry.deathRecipient != nullptr, GENERAL_ERROR);
        }
        listenerMap_.emplace(obj, entry);
        listenerSize = listenerMap_.size();
        // Post under the lock: SetUserRecognitionResult updates cachedResult_ under the same
        // mutex, so the catch-up event can never be overtaken by a newer result.
        syncResult = BuildUserRecognitionResultForCaller(entry.callerType, cachedResult_);
        IAM_LOGI("sync cached result to new listener, status:%{public}d", syncResult.status);
        handler->PostTask([listener, syncResult]() { listener->OnUserRecognitionEvent(syncResult); });
    }

    IAM_LOGI("RegisterListener success, listenerSize:%{public}zu", listenerSize);
    return SUCCESS;
}

int32_t UserRecognitionStateManager::UnregisterListener(const sptr<IUserRecognitionCallback> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    auto obj = listener->AsObject();
    IF_FALSE_LOGE_AND_RETURN_VAL(obj != nullptr, GENERAL_ERROR);

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto iter = listenerMap_.find(obj);
    if (iter == listenerMap_.end()) {
        IAM_LOGI("listener is not registered");
        return SUCCESS;
    }

    auto &entry = iter->second;
    if (obj != nullptr && entry.deathRecipient != nullptr) {
        obj->RemoveDeathRecipient(entry.deathRecipient);
    }
    listenerMap_.erase(iter);
    IAM_LOGI("UnregisterListener success, listenerSize:%{public}zu", listenerMap_.size());
    return SUCCESS;
}

void UserRecognitionStateManager::OnUserRecognitionEvent(const IpcUserRecognitionResult &result)
{
    IAM_LOGI("start, status:%{public}d userId:%{public}d", result.status, result.userId);
    std::vector<ListenerEntry> snapshot;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        snapshot.reserve(listenerMap_.size());
        for (const auto &iter : listenerMap_) {
            if (iter.second.callback != nullptr) {
                snapshot.push_back(iter.second);
            }
        }
    }
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
    handler->PostTask([snapshot = std::move(snapshot), result]() {
        for (const auto &entry : snapshot) {
            if (entry.callback == nullptr) {
                continue;
            }
            entry.callback->OnUserRecognitionEvent(BuildUserRecognitionResultForCaller(entry.callerType, result));
        }
    });
}

void UserRecognitionStateManager::SetUserRecognitionResult(IpcUserRecognitionResult result)
{
    IAM_LOGI("start, status:%{public}d userId:%{public}d", result.status, result.userId);
    if (result.status != static_cast<int32_t>(UserRecognitionStatus::MATCH)) {
        result.hasAuthTrustLevel = false;
        result.authTrustLevel = 0;
        result.authToken.clear();
    }

    bool shouldDispatch = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (!IsSameRecognitionResult(cachedResult_, result)) {
            cachedResult_ = result;
            shouldDispatch = true;
        }
    }
    if (shouldDispatch) {
        OnUserRecognitionEvent(result);
    } else {
        IAM_LOGI("dropping duplicate user recognition result");
    }
}

IpcUserRecognitionResult UserRecognitionStateManager::BuildUserRecognitionResultForCaller(int32_t callerType,
    IpcUserRecognitionResult result)
{
    if (callerType == Security::AccessToken::TOKEN_NATIVE) {
        return result;
    }
    result.authToken.clear();
    return result;
}

bool UserRecognitionStateManager::IsSameRecognitionResult(const IpcUserRecognitionResult &a,
    const IpcUserRecognitionResult &b)
{
    return a.status == b.status && a.userId == b.userId && a.userInfo == b.userInfo &&
        a.hasAuthTrustLevel == b.hasAuthTrustLevel && a.authTrustLevel == b.authTrustLevel &&
        a.authToken == b.authToken;
}

IpcUserRecognitionResult UserRecognitionStateManager::GetCachedUserRecognitionResult()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return cachedResult_;
}

IpcUserRecognitionResult UserRecognitionStateManager::GetCachedUserRecognitionResultForCaller(int32_t callerType)
{
    return BuildUserRecognitionResultForCaller(callerType, GetCachedUserRecognitionResult());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

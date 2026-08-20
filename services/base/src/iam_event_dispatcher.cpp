/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "iam_event_dispatcher.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "thread_handler.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_IAM_EVENT_DISPATCHER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS;
using namespace OHOS::UserIam::Common;

namespace {
struct DispatcherStore {
    std::mutex mutex;
    std::shared_ptr<IamEventDispatcher> instance;
};

DispatcherStore &GetStore()
{
    static DispatcherStore store;
    return store;
}
} // namespace

class IamEventDispatcherImpl final : public IamEventDispatcher,
                                     public std::enable_shared_from_this<IamEventDispatcherImpl> {
public:
    ~IamEventDispatcherImpl() override = default;
    friend std::shared_ptr<IamEventDispatcher> CreateIamEventDispatcher();

    void Post(EventId eventId, const IamEventData &data) override
    {
        std::vector<IamEventCallback> callbacks;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            auto it = subscribers_.find(eventId);
            if (it == subscribers_.end()) {
                IAM_LOGD("post event %{public}d with no subscriber", eventId);
                return;
            }
            callbacks.reserve(it->second.size());
            for (const auto &entry : it->second) {
                callbacks.push_back(entry.second);
            }
        }
        auto handler = ThreadHandler::GetSingleThreadInstance();
        IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
        handler->PostTask([callbacks = std::move(callbacks), data]() {
            for (const auto &cb : callbacks) {
                if (cb != nullptr) {
                    cb(data);
                }
            }
        });
    }

    std::unique_ptr<Subscription> Subscribe(EventId eventId, IamEventCallback callback) override
    {
        IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
        int64_t id = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            id = nextSubscribeId_++;
            subscribers_[eventId][id] = callback;
        }
        IAM_LOGI("subscribe event %{public}d subId %{public}lld", eventId, static_cast<long long>(id));
        auto cleanup = [weakSelf = weak_from_this(), eventId, id]() {
            auto self = weakSelf.lock();
            if (self != nullptr) {
                self->Unsubscribe(eventId, id);
            }
        };
        auto subscription = MakeUnique<Subscription>(cleanup);
        if (subscription == nullptr) {
            // Roll back the entry inserted above, otherwise the callback stays subscribed
            // forever with no handle to remove it.
            IAM_LOGE("make subscription fail, rollback subscribe");
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            Unsubscribe(eventId, id);
            return nullptr;
        }
        return subscription;
    }

private:
    IamEventDispatcherImpl() = default;
    void Unsubscribe(EventId eventId, int64_t id)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = subscribers_.find(eventId);
        if (it == subscribers_.end()) {
            return;
        }
        it->second.erase(id);
        if (it->second.empty()) {
            subscribers_.erase(it);
        }
    }
    std::recursive_mutex mutex_;
    std::unordered_map<EventId, std::unordered_map<int64_t, IamEventCallback>> subscribers_;
    int64_t nextSubscribeId_ = 1;
};

std::shared_ptr<IamEventDispatcher> CreateIamEventDispatcher()
{
    return std::shared_ptr<IamEventDispatcherImpl>(new IamEventDispatcherImpl());
}

IamEventDispatcher &GetIamEventDispatcher()
{
    auto &store = GetStore();
    std::shared_ptr<IamEventDispatcher> dispatcher;
    {
        std::lock_guard<std::mutex> lock(store.mutex);
        if (!store.instance) {
            store.instance = CreateIamEventDispatcher();
        }
        dispatcher = store.instance;
    }
    if (dispatcher == nullptr) {
        IAM_LOGE("IamEventDispatcher is null, abort");
        std::abort();
    }
    return *dispatcher;
}

void SetIamEventDispatcher(std::shared_ptr<IamEventDispatcher> dispatcher)
{
    auto &store = GetStore();
    std::lock_guard<std::mutex> lock(store.mutex);
    store.instance = std::move(dispatcher);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

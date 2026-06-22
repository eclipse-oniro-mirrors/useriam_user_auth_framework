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

#include "context_pool.h"

#include <fcntl.h>
#include <mutex>
#include <set>
#include <singleton.h>
#include <unordered_map>

#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "system_ability_listener.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_CONTEXT_POOL_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const uint32_t MAX_CONTEXT_NUM = 100;
bool GenerateRand(uint8_t *data, size_t len)
{
    FILE *fp = fopen("/dev/random", "rb");
    if (fp == nullptr) {
        IAM_LOGE("fopen read file fail");
        return false;
    }
    size_t readLen = fread(data, sizeof(uint8_t), len, fp);
    (void)fclose(fp);
    if (readLen != len) {
        IAM_LOGE("fread file failed");
        return false;
    }
    return true;
}
}
class ContextPoolImpl final : public ContextPool, public Singleton<ContextPoolImpl> {
public:
    bool Insert(const std::shared_ptr<Context> &context) override;
    bool Delete(uint64_t contextId) override;
    void CancelAll() const override;
    std::weak_ptr<Context> Select(uint64_t contextId) const override;
    std::vector<std::weak_ptr<Context>> Select(ContextType contextType) const override;
    std::shared_ptr<ScheduleNode> SelectScheduleNodeByScheduleId(uint64_t scheduleId) override;
    bool RegisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener) override;
    bool DeregisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener) override;
    void StartSubscribeOsAccountSaStatus() override;

private:
    void CheckPreemptContext(const std::shared_ptr<Context> &context);
    mutable std::recursive_mutex poolMutex_;
    std::unordered_map<uint64_t, std::shared_ptr<Context>> contextMap_;
    std::set<std::shared_ptr<ContextPoolListener>> listenerSet_;
    sptr<SystemAbilityListener> accountSaStatusListener_ {nullptr};
};

void ContextPoolImpl::CheckPreemptContext(const std::shared_ptr<Context> &context)
{
    if (context->GetContextType() != ContextType::CONTEXT_SIMPLE_AUTH) {
        return;
    }
    auto tempContextMap = contextMap_;
    for (auto iter = tempContextMap.begin(); iter != tempContextMap.end(); iter++) {
        if (iter->second == nullptr) {
            IAM_LOGE("context is nullptr");
            break;
        }
        if (iter->second->GetCallerName() == context->GetCallerName() &&
            iter->second->GetAuthType() == context->GetAuthType() &&
            iter->second->GetUserId() == context->GetUserId()) {
            IAM_LOGE("contextId:%{public}hx is preempted, newContextId:%{public}hx, mapSize:%{public}zu,"
                "callerName:%{public}s, userId:%{public}d, authType:%{public}d", static_cast<uint16_t>(iter->first),
                static_cast<uint16_t>(context->GetContextId()), tempContextMap.size(), context->GetCallerName().c_str(),
                context->GetUserId(), context->GetAuthType());
            iter->second->Stop();
            break;
        }
    }
}

bool ContextPoolImpl::Insert(const std::shared_ptr<Context> &context)
{
    if (context == nullptr) {
        IAM_LOGE("context is nullptr");
        return false;
    }
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    if (contextMap_.size() >= MAX_CONTEXT_NUM) {
        IAM_LOGE("context pool is full");
        return false;
    }
    CheckPreemptContext(context);
    uint64_t contextId = context->GetContextId();
    auto result = contextMap_.try_emplace(contextId, context);
    if (!result.second) {
        return false;
    }
    auto tempListenerSet = listenerSet_;
    for (const auto &listener : tempListenerSet) {
        if (listener != nullptr) {
            listener->OnContextPoolInsert(context);
        }
    }
    return true;
}

bool ContextPoolImpl::Delete(uint64_t contextId)
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    auto iter = contextMap_.find(contextId);
    if (iter == contextMap_.end()) {
        IAM_LOGE("context not found");
        return false;
    }
    auto tempContext = iter->second;
    contextMap_.erase(iter);
    auto tempListenerSet = listenerSet_;
    for (const auto &listener : tempListenerSet) {
        if (listener != nullptr) {
            listener->OnContextPoolDelete(tempContext);
        }
    }
    return true;
}

void ContextPoolImpl::CancelAll() const
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    auto tempContextMap = contextMap_;
    for (const auto &context : tempContextMap) {
        if (context.second == nullptr) {
            continue;
        }
        IAM_LOGI("cancel context %{public}s", GET_MASKED_STRING(context.second->GetContextId()).c_str());
        if (!context.second->Stop()) {
            IAM_LOGE("cancel context %{public}s fail", GET_MASKED_STRING(context.second->GetContextId()).c_str());
        }
    }
}

std::weak_ptr<Context> ContextPoolImpl::Select(uint64_t contextId) const
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    std::weak_ptr<Context> result;
    auto iter = contextMap_.find(contextId);
    if (iter != contextMap_.end()) {
        result = iter->second;
    }
    return result;
}

std::vector<std::weak_ptr<Context>> ContextPoolImpl::Select(ContextType contextType) const
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    std::vector<std::weak_ptr<Context>> result;
    for (const auto &context : contextMap_) {
        if (context.second == nullptr) {
            continue;
        }
        if (context.second->GetContextType() == contextType) {
            result.emplace_back(context.second);
        }
    }
    return result;
}

std::shared_ptr<ScheduleNode> ContextPoolImpl::SelectScheduleNodeByScheduleId(uint64_t scheduleId)
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    for (const auto &context : contextMap_) {
        if (context.second == nullptr) {
            continue;
        }
        auto node = context.second->GetScheduleNode(scheduleId);
        if (node != nullptr) {
            return node;
        }
    }

    IAM_LOGE("not found");
    return nullptr;
}

bool ContextPoolImpl::RegisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener)
{
    if (listener == nullptr) {
        IAM_LOGE("listener is nullptr");
        return false;
    }
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    listenerSet_.insert(listener);
    return true;
}

bool ContextPoolImpl::DeregisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener)
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    return listenerSet_.erase(listener) == 1;
}

void ContextPoolImpl::StartSubscribeOsAccountSaStatus()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    if (accountSaStatusListener_ != nullptr) {
        return;
    }
    accountSaStatusListener_ = SystemAbilityListener::Subscribe(
        "OsAccountService", SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN,
        []() {},
        []() { ContextPool::Instance().CancelAll(); });
    IF_FALSE_LOGE_AND_RETURN(accountSaStatusListener_ != nullptr);
}

ContextPool &ContextPool::Instance()
{
    return ContextPoolImpl::GetInstance();
}

uint64_t ContextPool::GetNewContextId()
{
    static constexpr uint32_t MAX_TRY_TIMES = 10;
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    uint64_t contextId = 0;
    unsigned char *contextIdPtr = static_cast<unsigned char *>(static_cast<void *>(&contextId));
    for (uint32_t i = 0; i < MAX_TRY_TIMES; i++) {
        bool genRandRet = GenerateRand(contextIdPtr, sizeof(uint64_t));
        if (!genRandRet) {
            IAM_LOGE("generate rand fail");
            return 0;
        }
        if (contextId == 0 || contextId == REUSE_AUTH_RESULT_CONTEXT_ID ||
            ContextPool::Instance().Select(contextId).lock() != nullptr) {
            IAM_LOGE("invalid or duplicate context id");
            continue;
        }
        break;
    }
    return contextId;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

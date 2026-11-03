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

#include <algorithm>
#include <chrono>
#include <deque>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <singleton.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "system_ability_listener.h"
#include "thread_handler.h"

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

bool IsSameCallerDuplicate(const Context &incoming, const Context &existing)
{
    if (!incoming.IsPrimaryContext() || !existing.IsPrimaryContext() ||
        incoming.GetCallerName() != existing.GetCallerName() ||
        incoming.GetContextType() != existing.GetContextType() ||
        incoming.GetAuthType() != existing.GetAuthType() ||
        incoming.GetUserId() != existing.GetUserId()) {
        return false;
    }
    IAM_LOGI("context ****%{public}hx superseded by newer request ****%{public}hx from same caller",
        static_cast<uint16_t>(existing.GetContextId()),
        static_cast<uint16_t>(incoming.GetContextId()));
    return true;
}
}
class ContextPoolImpl final : public ContextPool, public DelayedRefSingleton<ContextPoolImpl> {
public:
    bool Schedule(const std::shared_ptr<Context> &context) override;
    void Cancel(uint64_t contextId) override;
    bool Delete(uint64_t contextId) override;
    void CancelAll() override;
    void NotifyPreemptStateChanged() override;
    std::weak_ptr<Context> Select(uint64_t contextId) const override;
    std::vector<std::weak_ptr<Context>> Select(ContextType contextType) const override;
    std::shared_ptr<ScheduleNode> SelectScheduleNodeByScheduleId(uint64_t scheduleId) override;
    void StartSubscribeOsAccountSaStatus() override;
#ifdef IAM_TEST_ENABLE
    std::vector<std::weak_ptr<Context>> SelectAll() const override;
#endif

private:
    DECLARE_DELAYED_REF_SINGLETON(ContextPoolImpl);

    struct AdmissionPlan {
        std::map<uint64_t, std::shared_ptr<Context>> toStop;
        std::vector<std::shared_ptr<Context>> toStart;
    };
    void PromoteWaitingLocked(AdmissionPlan &plan);
    void ExecutePlan(AdmissionPlan plan);
    static bool StopIfPooled(uint64_t contextId);
    static void StartIfPooled(uint64_t contextId);
    std::weak_ptr<Context> SelectLocked(uint64_t contextId) const;

    mutable std::recursive_mutex poolMutex_;
    std::unordered_map<uint64_t, std::shared_ptr<Context>> runningContexts_;
    sptr<SystemAbilityListener> accountSaStatusListener_ {nullptr};
    std::deque<std::shared_ptr<Context>> waitingFifo_;
    std::unordered_set<uint64_t> cancelRequestedIds_;
};

ContextPoolImpl::ContextPoolImpl() = default;

ContextPoolImpl::~ContextPoolImpl() = default;

ContextPool &ContextPool::Instance()
{
    return ContextPoolImpl::GetInstance();
}

ContextPool::Cleaner::Cleaner(const std::shared_ptr<Context> &context)
    : contextId_(context != nullptr ? context->GetContextId() : INVALID_CONTEXT_ID)
{
}

void ContextPool::Cleaner::operator()()
{
    IAM_LOGD("start");
    if (contextId_ == INVALID_CONTEXT_ID) {
        IAM_LOGE("invalid context id");
        return;
    }
    auto result = ContextPool::Instance().Delete(contextId_);
    IAM_LOGI("context ****%{public}hx deleted %{public}s", static_cast<uint16_t>(contextId_), result ? "succ" : "fail");
};

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

bool ContextPoolImpl::Schedule(const std::shared_ptr<Context> &context)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(context != nullptr, false);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(handler != nullptr, false);
    AdmissionPlan plan;
    {
        std::lock_guard<std::recursive_mutex> lock(poolMutex_);
        if (runningContexts_.size() + waitingFifo_.size() >= MAX_CONTEXT_NUM) {
            IAM_LOGE("context pool is full");
            return false;
        }
        if (SelectLocked(context->GetContextId()).lock() != nullptr) {
            IAM_LOGE("failed to insert context ****%{public}hx",
                static_cast<uint16_t>(context->GetContextId()));
            return false;
        }
        waitingFifo_.push_back(context);
        PromoteWaitingLocked(plan);
    }
    ExecutePlan(std::move(plan));
    return true;
}

void ContextPoolImpl::Cancel(uint64_t contextId)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
    {
        std::lock_guard<std::recursive_mutex> lock(poolMutex_);
        cancelRequestedIds_.insert(contextId);
    }
    handler->PostTask([contextId]() {
        IAM_LOGI("cancel context ****%{public}hx", static_cast<uint16_t>(contextId));
        ContextPoolImpl::StopIfPooled(contextId);
    });
}

bool ContextPoolImpl::Delete(uint64_t contextId)
{
    AdmissionPlan plan;
    std::shared_ptr<Context> detached;
    {
        std::lock_guard<std::recursive_mutex> lock(poolMutex_);
        auto waitingIter = std::find_if(waitingFifo_.begin(), waitingFifo_.end(),
            [contextId](const std::shared_ptr<Context> &context) {
                return context != nullptr && context->GetContextId() == contextId;
            });
        bool removedFromWaiting = waitingIter != waitingFifo_.end();
        if (removedFromWaiting) {
            detached = std::move(*waitingIter);
            waitingFifo_.erase(waitingIter);
            IAM_LOGI("context ****%{public}hx was still waiting, removed from queue",
                static_cast<uint16_t>(contextId));
        }
        auto runningIter = runningContexts_.find(contextId);
        bool removedFromRunning = runningIter != runningContexts_.end();
        if (removedFromRunning) {
            detached = std::move(runningIter->second);
            runningContexts_.erase(runningIter);
        }
        if (!removedFromWaiting && !removedFromRunning) {
            IAM_LOGE("context not found");
            return false;
        }
        PromoteWaitingLocked(plan);
    }
    ExecutePlan(std::move(plan));
    return true;
}

void ContextPoolImpl::CancelAll()
{
    IAM_LOGI("start");
    std::vector<uint64_t> contextIds;
    {
        std::lock_guard<std::recursive_mutex> lock(poolMutex_);
        contextIds.reserve(runningContexts_.size() + waitingFifo_.size());
        for (const auto &[contextId, context] : runningContexts_) {
            if (context != nullptr) {
                contextIds.push_back(contextId);
            }
        }
        for (const auto &context : waitingFifo_) {
            if (context != nullptr) {
                contextIds.push_back(context->GetContextId());
            }
        }
    }
    for (auto contextId : contextIds) {
        Cancel(contextId);
    }
}

void ContextPoolImpl::NotifyPreemptStateChanged()
{
    IAM_LOGI("start");
    AdmissionPlan plan;
    {
        std::lock_guard<std::recursive_mutex> lock(poolMutex_);
        PromoteWaitingLocked(plan);
    }
    ExecutePlan(std::move(plan));
}

std::weak_ptr<Context> ContextPoolImpl::Select(uint64_t contextId) const
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    return SelectLocked(contextId);
}

std::vector<std::weak_ptr<Context>> ContextPoolImpl::Select(ContextType contextType) const
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    std::vector<std::weak_ptr<Context>> result;
    result.reserve(runningContexts_.size() + waitingFifo_.size());
    for (const auto &[contextId, context] : runningContexts_) {
        if (context == nullptr) {
            continue;
        }
        if (context->GetContextType() == contextType) {
            result.emplace_back(context);
        }
    }
    for (const auto &context : waitingFifo_) {
        if (context == nullptr) {
            continue;
        }
        if (context->GetContextType() == contextType) {
            result.emplace_back(context);
        }
    }
    return result;
}

std::shared_ptr<ScheduleNode> ContextPoolImpl::SelectScheduleNodeByScheduleId(uint64_t scheduleId)
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    for (const auto &[contextId, context] : runningContexts_) {
        if (context == nullptr) {
            continue;
        }
        auto node = context->GetScheduleNode(scheduleId);
        if (node != nullptr) {
            return node;
        }
    }

    IAM_LOGE("not found");
    return nullptr;
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

#ifdef IAM_TEST_ENABLE
std::vector<std::weak_ptr<Context>> ContextPoolImpl::SelectAll() const
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    std::vector<std::weak_ptr<Context>> result;
    result.reserve(runningContexts_.size() + waitingFifo_.size());
    for (const auto &[contextId, context] : runningContexts_) {
        if (context != nullptr) {
            result.emplace_back(context);
        }
    }
    for (const auto &context : waitingFifo_) {
        if (context != nullptr) {
            result.emplace_back(context);
        }
    }
    return result;
}
#endif

void ContextPoolImpl::PromoteWaitingLocked(AdmissionPlan &plan)
{
    if (waitingFifo_.empty()) {
        return;
    }
    std::vector<std::shared_ptr<Context>> predecessors;
    predecessors.reserve(runningContexts_.size());
    for (const auto &[contextId, context] : runningContexts_) {
        if (context != nullptr) {
            predecessors.push_back(context);
        }
    }
    for (auto it = waitingFifo_.begin(); it != waitingFifo_.end();) {
        auto waiter = *it;
        if (waiter == nullptr) {
            it = waitingFifo_.erase(it);
            continue;
        }
        std::vector<std::pair<uint64_t, std::shared_ptr<Context>>> pendingVictims;
        std::vector<std::weak_ptr<Context>> visible;
        for (const auto &member : predecessors) {
            if (member == nullptr) {
                continue;
            }
            bool canCollect = waiter->GetCreateTime() > member->GetCreateTime();
            if (canCollect && IsSameCallerDuplicate(*waiter, *member)) {
                plan.toStop.emplace(member->GetContextId(), member);
                continue;
            }
            if (canCollect && member->GetPreemptDecision(*waiter) == PreemptDecision::STOP_NOW) {
                pendingVictims.emplace_back(member->GetContextId(), member);
                continue;
            }
            visible.emplace_back(member);
        }
        predecessors.push_back(waiter);
        for (auto &[victimId, victim] : pendingVictims) {
            plan.toStop.emplace(victimId, victim);
        }
        if (!waiter->CanStart(visible)) {
            ++it;
            continue;
        }

        IAM_LOGI("pool admits context ****%{public}hx",
            static_cast<uint16_t>(waiter->GetContextId()));
        plan.toStart.push_back(waiter);
        runningContexts_.emplace(waiter->GetContextId(), waiter);
        it = waitingFifo_.erase(it);
    }
}

void ContextPoolImpl::ExecutePlan(AdmissionPlan plan)
{
    if (plan.toStop.empty() && plan.toStart.empty()) {
        return;
    }
    auto handler = ThreadHandler::GetSingleThreadInstance();
    if (handler == nullptr) {
        IAM_LOGE("thread handler unavailable, drop admission plan");
        return;
    }
    for (const auto &iter : plan.toStop) {
        uint64_t contextId = iter.second->GetContextId();
        handler->PostTask([contextId]() {
            IAM_LOGI("preempted by new request, stop context ****%{public}hx",
                static_cast<uint16_t>(contextId));
            if (!StopIfPooled(contextId)) {
                IAM_LOGE("preemptive stop fail, context ****%{public}hx",
                    static_cast<uint16_t>(contextId));
            }
        });
    }
    for (const auto &context : plan.toStart) {
        uint64_t contextId = context->GetContextId();
        handler->PostTask([contextId]() {
            StartIfPooled(contextId);
        });
    }
}

bool ContextPoolImpl::StopIfPooled(uint64_t contextId)
{
    {
        std::lock_guard<std::recursive_mutex> lock(GetInstance().poolMutex_);
        GetInstance().cancelRequestedIds_.erase(contextId);
    }
    auto context = GetInstance().Select(contextId).lock();
    if (context == nullptr) {
        IAM_LOGI("cancel context ****%{public}hx fail or already terminated", static_cast<uint16_t>(contextId));
        return false;
    }
    return context->Stop();
}

void ContextPoolImpl::StartIfPooled(uint64_t contextId)
{
    std::shared_ptr<Context> context;
    {
        auto &pool = GetInstance();
        std::lock_guard<std::recursive_mutex> lock(pool.poolMutex_);
        auto iter = pool.runningContexts_.find(contextId);
        bool cancelRequested = pool.cancelRequestedIds_.find(contextId) != pool.cancelRequestedIds_.end();
        if (iter == pool.runningContexts_.end() || iter->second == nullptr || cancelRequested) {
            return;
        }
        context = iter->second;
    }
    if (!context->Start()) {
        IAM_LOGE("start fail, context ****%{public}hx", static_cast<uint16_t>(contextId));
        context->OnStartFailed(context->GetLatestError());
    }
}

std::weak_ptr<Context> ContextPoolImpl::SelectLocked(uint64_t contextId) const
{
    auto iter = runningContexts_.find(contextId);
    if (iter != runningContexts_.end()) {
        return iter->second;
    }
    auto waiting = std::find_if(waitingFifo_.begin(), waitingFifo_.end(),
        [contextId](const std::shared_ptr<Context> &context) {
            return context != nullptr && context->GetContextId() == contextId;
        });
    if (waiting != waitingFifo_.end()) {
        return *waiting;
    }
    return {};
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

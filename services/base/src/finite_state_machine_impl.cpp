/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "finite_state_machine_impl.h"

#include <set>

#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_FINITE_STATE_MACHINE_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS;
FiniteStateMachineImpl::FiniteStateMachineImpl(std::string name, uint32_t initialState, TransitionMap &transitionMap,
    EnterMap &enterMap, LeaveMap &leaveMap)
    : name_(std::move(name)),
      currentState_(initialState),
      threadHandler_(ThreadHandler::GetSingleThreadInstance()),
      transitionMap_(std::move(transitionMap)),
      enterMap_(std::move(enterMap)),
      leaveMap_(std::move(leaveMap))
{
    IAM_LOGD("fsm %{public}s created for %{public}zu transitions", name_.c_str(), transitionMap_.size());
}

FiniteStateMachineImpl::~FiniteStateMachineImpl()
{
    pendingEvents_.Clear();
    IAM_LOGD("fsm %{public}s destroyed for %{public}zu transitions", name_.c_str(), transitionMap_.size());
}

void FiniteStateMachineImpl::Schedule(uint32_t event)
{
    if (threadHandler_ == nullptr) {
        IAM_LOGE("machine %{public}s 's threadHandler not set", GetMachineName().c_str());
        return;
    }
    pendingEvents_.Push(event);
    IAM_LOGD("fsm %{public}s new schedule event input:%{public}u", name_.c_str(), event);
    threadHandler_->PostTask([self = weak_from_this(), this]() {
        if (auto machine = self.lock(); machine != nullptr) {
            Inner inner(machine);
            ScheduleInner(inner);
        }
    });
}

void FiniteStateMachineImpl::ScheduleInner(FiniteStateMachine &machine)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (uint32_t runTimes = 0; runTimes < FiniteStateMachineImpl::MAX_SCHEDULE_TIMES; runTimes++) {
        uint32_t event = 0;
        bool result = pendingEvents_.Pop(event);
        if (!result) {
            IAM_LOGD("fsm %{public}s pop event fail", name_.c_str());
            break;
        }

        uint32_t oldState = currentState_;
        auto iter = transitionMap_.find(GetTransitionIndex(currentState_, event));
        if (iter != transitionMap_.end()) {
            auto invoker = iter->second.second;
            if (invoker) {
                invoker(machine, event);
            }
            currentState_ = iter->second.first;
        }

        DealWithStateLeaveAndEnter(machine, oldState, currentState_);

        IAM_LOGI("fsm %{public}s schedule [state:%{public}u] + [event:%{public}u] -> [nextState:%{public}u]",
            name_.c_str(), oldState, event, currentState_);
        if (runTimes >= FiniteStateMachineImpl::MAX_SCHEDULE_TIMES) {
            IAM_LOGE("fsm %{public}s schedule too many times", name_.c_str());
            break;
        }
    }
}

void FiniteStateMachineImpl::DealWithStateLeaveAndEnter(FiniteStateMachine &machine, uint32_t oldState,
    uint32_t newState)
{
    if (oldState == newState) {
        return;
    }
    if (auto iter = leaveMap_.find(oldState); iter != leaveMap_.end()) {
        if (auto invoker = iter->second; invoker) {
            invoker(machine, oldState);
        }
    }

    if (auto iter = enterMap_.find(currentState_); iter != enterMap_.end()) {
        if (auto invoker = iter->second; invoker) {
            invoker(machine, currentState_);
        }
    }
}

uint32_t FiniteStateMachineImpl::GetCurrentState() const
{
    return currentState_;
}

uint32_t FiniteStateMachineImpl::EnsureCurrentState()
{
    if (threadHandler_) {
        threadHandler_->EnsureTask([]() {});
    }

    return currentState_;
}

const std::string &FiniteStateMachineImpl::GetMachineName() const
{
    return name_;
}

void FiniteStateMachineImpl::SetThreadHandler(const std::shared_ptr<ThreadHandler> &threadHandler)
{
    threadHandler_ = threadHandler;
}

FiniteStateMachineImpl::Inner::Inner(std::shared_ptr<FiniteStateMachineImpl> &machine) : machine_(machine)
{
}

void FiniteStateMachineImpl::Inner::Schedule(uint32_t event)
{
    machine_->pendingEvents_.Push(event);
}

uint32_t FiniteStateMachineImpl::Inner::GetCurrentState() const
{
    return machine_->GetCurrentState();
}

uint32_t FiniteStateMachineImpl::Inner::EnsureCurrentState()
{
    return machine_->GetCurrentState();
}

const std::string &FiniteStateMachineImpl::Inner::GetMachineName() const
{
    return machine_->GetMachineName();
}

void FiniteStateMachineImpl::Inner::SetThreadHandler(const std::shared_ptr<ThreadHandler> &threadHandler)
{
    IAM_LOGE("can not set thread handler inner");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

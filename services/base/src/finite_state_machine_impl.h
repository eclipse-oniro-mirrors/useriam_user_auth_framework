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

#ifndef IAM_FINITE_STATE_MACHINE_IMPL_H
#define IAM_FINITE_STATE_MACHINE_IMPL_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>

#include "nocopyable.h"
#include "safe_queue.h"

#include "finite_state_machine.h"
#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class FiniteStateMachineImpl final : public FiniteStateMachine,
                                     public std::enable_shared_from_this<FiniteStateMachineImpl>,
                                     public NoCopyable {
public:
    class Inner;
    using TransitionMap = std::unordered_map<uint64_t, std::pair<uint32_t, FiniteStateMachine::Action>>;
    using EnterMap = std::unordered_map<uint32_t, FiniteStateMachine::Action>;
    using LeaveMap = std::unordered_map<uint32_t, FiniteStateMachine::Action>;

    FiniteStateMachineImpl(std::string name, uint32_t initialState, TransitionMap &transitionMap, EnterMap &enterMap,
        LeaveMap &leaveMap);
    ~FiniteStateMachineImpl() override;

    void Schedule(uint32_t event) override;
    uint32_t GetCurrentState() const override;
    uint32_t EnsureCurrentState() override;
    void SetThreadHandler(const std::shared_ptr<ThreadHandler> &threadHandler) override;
    const std::string &GetMachineName() const override;
    friend class FiniteStateMachineBuilder;

private:
    static constexpr uint32_t MAX_SCHEDULE_TIMES = 100;
    constexpr static inline uint64_t GetTransitionIndex(uint32_t state, uint32_t event)
    {
        constexpr uint32_t uint32WidthLen = 32;
        return (static_cast<uint64_t>(state) << uint32WidthLen) | event;
    }
    void ScheduleInner(FiniteStateMachine &machine);
    void DealWithStateLeaveAndEnter(FiniteStateMachine &machine, uint32_t oldState, uint32_t newState);

    const std::string name_;
    uint32_t currentState_;
    std::shared_ptr<ThreadHandler> threadHandler_;
    TransitionMap transitionMap_;
    FiniteStateMachineImpl::EnterMap enterMap_;
    FiniteStateMachineImpl::LeaveMap leaveMap_;

    std::recursive_mutex mutex_;
    SafeQueue<uint32_t> pendingEvents_ {};
};

class FiniteStateMachineImpl::Inner final : public FiniteStateMachine, public NoCopyable {
public:
    explicit Inner(std::shared_ptr<FiniteStateMachineImpl> &machine);
    ~Inner() override = default;
    void Schedule(uint32_t event) override;
    uint32_t GetCurrentState() const override;
    uint32_t EnsureCurrentState() override;
    const std::string &GetMachineName() const override;
    void SetThreadHandler(const std::shared_ptr<ThreadHandler> &threadHandler) override;

private:
    std::shared_ptr<FiniteStateMachineImpl> &machine_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_FINITE_STATE_MACHINE_IMPL_H
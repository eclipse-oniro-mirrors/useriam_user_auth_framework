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

#ifndef IAM_FINITE_STATE_MACHINE_BUILDER_H
#define IAM_FINITE_STATE_MACHINE_BUILDER_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "nocopyable.h"

#include "finite_state_machine_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class FiniteStateMachineBuilder final : public FiniteStateMachine::Builder,
                                        public std::enable_shared_from_this<FiniteStateMachineBuilder>,
                                        public NoCopyable {
public:
    FiniteStateMachineBuilder(std::string name, uint32_t initialState);
    ~FiniteStateMachineBuilder() override;
    std::shared_ptr<FiniteStateMachine::Builder> MakeTransition(uint32_t state, uint32_t event, uint32_t nextState,
        const FiniteStateMachine::Action &action) override;
    std::shared_ptr<FiniteStateMachine::Builder> MakeTransition(uint32_t state, uint32_t event,
        uint32_t nextState) override;
    std::shared_ptr<Builder> MakeOnStateEnter(uint32_t state, const FiniteStateMachine::Action &action) override;
    std::shared_ptr<Builder> MakeOnStateLeave(uint32_t state, const FiniteStateMachine::Action &action) override;
    std::shared_ptr<Builder> SetOwnerLifetime(const std::weak_ptr<void> &ownerLifetime) override;
    std::shared_ptr<FiniteStateMachine> Build() override;

private:
    std::string name_;
    uint32_t initstate_{0};
    bool valid_{false};
    std::optional<std::weak_ptr<void>> ownerLifetime_ {};
    FiniteStateMachineImpl::TransitionMap transitionMap_;
    FiniteStateMachineImpl::EnterMap enterMap_;
    FiniteStateMachineImpl::LeaveMap leaveMap_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_FINITE_STATE_MACHINE_BUILDER_H
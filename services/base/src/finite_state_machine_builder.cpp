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
#include "finite_state_machine_builder.h"

#include <future>
#include <mutex>
#include <queue>
#include <set>
#include <unordered_map>

#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_FINITE_STATE_MACHINE_BUILDER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS;
FiniteStateMachineBuilder::FiniteStateMachineBuilder(std::string name, uint32_t initialState)
    : name_(std::move(name)),
      initstate_(initialState),
      valid_(true)
{
}

FiniteStateMachineBuilder::~FiniteStateMachineBuilder() = default;

std::shared_ptr<FiniteStateMachine::Builder> FiniteStateMachineBuilder::MakeTransition(uint32_t state, uint32_t event,
    uint32_t nextState, const FiniteStateMachine::Action &action)
{
    auto ret = transitionMap_.try_emplace(FiniteStateMachineImpl::GetTransitionIndex(state, event), nextState, action);
    if (!ret.second) {
        IAM_LOGE("%{public}s state %{public}u and event %{public}u insert failed", name_.c_str(), state, event);
        valid_ = false;
    }
    return shared_from_this();
}

std::shared_ptr<FiniteStateMachine::Builder> FiniteStateMachineBuilder::MakeTransition(uint32_t state, uint32_t event,
    uint32_t nextState)
{
    MakeTransition(state, event, nextState, nullptr);
    return shared_from_this();
}

std::shared_ptr<FiniteStateMachine::Builder> FiniteStateMachineBuilder::MakeOnStateEnter(uint32_t state,
    const FiniteStateMachine::Action &action)
{
    auto ret = enterMap_.try_emplace(state, action);
    if (!ret.second) {
        IAM_LOGE("%{public}s enter state action %{public}u insert failed", name_.c_str(), state);
        valid_ = false;
    }
    return shared_from_this();
}

std::shared_ptr<FiniteStateMachine::Builder> FiniteStateMachineBuilder::MakeOnStateLeave(uint32_t state,
    const FiniteStateMachine::Action &action)
{
    auto ret = leaveMap_.try_emplace(state, action);
    if (!ret.second) {
        IAM_LOGE("%{public}s leave state action %{public}u insert failed", name_.c_str(), state);
        valid_ = false;
    }
    return shared_from_this();
}

std::shared_ptr<FiniteStateMachine> FiniteStateMachineBuilder::Build()
{
    if (!valid_) {
        IAM_LOGI("machine %{public}s builded failed", name_.c_str());
        return nullptr;
    }
    valid_ = false;
    return Common::MakeShared<FiniteStateMachineImpl>(name_, initstate_, transitionMap_, enterMap_, leaveMap_);
}

std::shared_ptr<FiniteStateMachine::Builder> FiniteStateMachine::Builder::New(const std::string &name,
    uint32_t initialState)
{
    return Common::MakeShared<FiniteStateMachineBuilder>(name, initialState);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

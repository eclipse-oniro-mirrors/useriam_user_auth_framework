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

#ifndef IAM_STATE_MACHINE_H
#define IAM_STATE_MACHINE_H

#include <cstdint>
#include <memory>
#include <string>

#include "nocopyable.h"

#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class FiniteStateMachine {
public:
    using Action = std::function<void(FiniteStateMachine &, uint32_t)>;
    class Builder;
    virtual ~FiniteStateMachine() = default;
    virtual void Schedule(uint32_t event) = 0;
    virtual uint32_t GetCurrentState() const = 0;
    virtual uint32_t EnsureCurrentState() = 0;
    virtual void SetThreadHandler(const std::shared_ptr<ThreadHandler> &threadHandler) = 0;
    virtual const std::string &GetMachineName() const = 0;
    virtual void AttachOwnerLifetime(const std::weak_ptr<void> &ownerLifetime) = 0;
};

class FiniteStateMachine::Builder {
public:
    static std::shared_ptr<Builder> New(const std::string &name, uint32_t initialState);
    virtual ~Builder() = default;
    virtual std::shared_ptr<Builder> MakeTransition(uint32_t state, uint32_t event, uint32_t nextState,
        const FiniteStateMachine::Action &action) = 0;

    virtual std::shared_ptr<Builder> MakeTransition(uint32_t state, uint32_t event, uint32_t nextState) = 0;

    virtual std::shared_ptr<Builder> MakeOnStateEnter(uint32_t state, const FiniteStateMachine::Action &action) = 0;

    virtual std::shared_ptr<Builder> MakeOnStateLeave(uint32_t state, const FiniteStateMachine::Action &action) = 0;

    virtual std::shared_ptr<FiniteStateMachine> Build() = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_STATE_MACHINE_H
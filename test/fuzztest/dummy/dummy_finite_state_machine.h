/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DUMMY_FINITE_STATE_MACHINE_H
#define DUMMY_FINITE_STATE_MACHINE_H

#include "authentication.h"

#undef private

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyFiniteStateMachine : public FiniteStateMachine {
public:
    ~DummyFiniteStateMachine() = default;
    void Schedule(uint32_t event) {};
    uint32_t GetCurrentState() const
    {
        return 0;
    };
    uint32_t EnsureCurrentState()
    {
        return 0;
    };
    void SetThreadHandler(const std::shared_ptr<ThreadHandler> &threadHandler) {};
    void AttachOwnerLifetime(const std::weak_ptr<void> &ownerLifetime) {};
    const std::string &GetMachineName() const
    {
        static std::string machineName = "MyMachineName";
        return machineName;
    };
};

}
} // UserAuth
} // UserIam
} // OHOS

#endif // DUMMY_FINITE_STATE_MACHINE_H
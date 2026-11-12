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

#ifndef DUMMY_RESOURCE_NODE_H
#define DUMMY_RESOURCE_NODE_H

#include "resource_node.h"

#undef private

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyResourceNode : public ResourceNode {
public:
    uint64_t GetExecutorIndex() const
    {
        return 0;
    };
    std::string GetOwnerDeviceId() const
    {
        return "";
    };
    uint32_t GetOwnerPid() const
    {
        return 0;
    };
    AuthType GetAuthType() const
    {
        return static_cast<AuthType>(0);
    };
    ExecutorRole GetExecutorRole() const
    {
        return static_cast<ExecutorRole>(0);
    };
    uint64_t GetExecutorSensorHint() const
    {
        return 0;
    };
    uint64_t GetExecutorMatcher() const
    {
        return 0;
    };
    ExecutorSecureLevel GetExecutorEsl() const
    {
        return static_cast<ExecutorSecureLevel>(0);
    };
    std::vector<uint8_t> GetExecutorPublicKey() const
    {
        return {};
    };
    std::string GetExecutorDeviceUdid() const
    {
        return "";
    };
    int32_t BeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command)
    {
        return 0;
    };
    int32_t EndExecute(uint64_t scheduleId, const Attributes &command)
    {
        return 0;
    };
    int32_t SetProperty(const Attributes &properties, Attributes &values)
    {
        return 0;
    };
    int32_t GetProperty(const Attributes &condition, Attributes &values)
    {
        return 0;
    };
    int32_t SendData(uint64_t scheduleId, const Attributes &data)
    {
        return 0;
    };
    void DeleteFromEngine()
    {};
    void DetachFromEngine()
    {};

    static std::shared_ptr<ResourceNode> MakeNewResource(const ExecutorRegisterInfo &info,
        const std::shared_ptr<IExecutorCallback> &callback, std::vector<uint64_t> &templateIdList,
        std::vector<uint8_t> &fwkPublicKey)
        {
            return nullptr;
        };
    
    static std::shared_ptr<ResourceNode> CreateWithExecuteIndex(uint64_t executorId, AuthType authType,
        ExecutorRole executorRole, IExecutorCallback &callback)
    {
        auto node = std::make_shared<DummyResourceNode>();
        return node;
    };
};
}
} // UserAuth
} // UserIam
} // OHOS

#endif // DUMMY_RESOURCE_NODE_H
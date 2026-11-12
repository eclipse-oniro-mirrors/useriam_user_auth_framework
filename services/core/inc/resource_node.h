/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef IAM_RESOURCE_NODE_H
#define IAM_RESOURCE_NODE_H

#include <cstdint>
#include <memory>
#include <vector>

#include "attributes.h"
#include "co_auth_interface.h"
#include "iexecutor_callback.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ResourceNode {
public:
    using ExecutorRegisterInfo = CoAuthInterface::ExecutorRegisterInfo;
    virtual ~ResourceNode() = default;
    virtual uint64_t GetExecutorIndex() const = 0;
    virtual std::string GetOwnerDeviceId() const = 0;
    virtual uint32_t GetOwnerPid() const = 0;
    virtual AuthType GetAuthType() const = 0;
    virtual ExecutorRole GetExecutorRole() const = 0;
    virtual uint64_t GetExecutorSensorHint() const = 0;
    virtual uint64_t GetExecutorMatcher() const = 0;
    virtual ExecutorSecureLevel GetExecutorEsl() const = 0;
    virtual std::vector<uint8_t> GetExecutorPublicKey() const = 0;
    virtual std::string GetExecutorDeviceUdid() const = 0;
    virtual int32_t BeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command) = 0;
    virtual int32_t EndExecute(uint64_t scheduleId, const Attributes &command) = 0;
    virtual int32_t SetProperty(const Attributes &properties, Attributes &values) = 0;
    virtual int32_t GetProperty(const Attributes &condition, Attributes &values) = 0;
    virtual int32_t SendData(uint64_t scheduleId, const Attributes &data) = 0;
    virtual void DeleteFromEngine() = 0;
    virtual void DetachFromEngine() = 0;

    static std::shared_ptr<ResourceNode> MakeNewResource(const ExecutorRegisterInfo &info,
        const std::shared_ptr<IExecutorCallback> &callback, std::vector<uint64_t> &templateIdList,
        std::vector<uint8_t> &fwkPublicKey);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_RESOURCE_NODE_H
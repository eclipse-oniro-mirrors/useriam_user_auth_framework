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

#ifndef COMMON_DUMMY_H
#define COMMON_DUMMY_H

#include "resource_node_pool.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_RESOURCE_NODE_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class DummyResourceNode final : public ResourceNode {
public:
    using ExecutorRegisterInfo = CoAuthInterface::ExecutorRegisterInfo;
    uint64_t GetExecutorIndex() const
    {
        IAM_LOGI("start");
        static uint64_t index = 0;
        ++index;
        return index;
    }

    std::string GetOwnerDeviceId() const
    {
        IAM_LOGI("start");
        return "";
    }

    uint32_t GetOwnerPid() const
    {
        IAM_LOGI("start");
        return 0;
    }

    AuthType GetAuthType() const
    {
        IAM_LOGI("start");
        return PIN;
    }

    ExecutorRole GetExecutorRole() const
    {
        IAM_LOGI("start");
        return SCHEDULER;
    }

    uint64_t GetExecutorSensorHint() const
    {
        IAM_LOGI("start");
        return 0;
    }
    
    uint64_t GetExecutorMatcher() const
    {
        IAM_LOGI("start");
        return 0;
    }

    ExecutorSecureLevel GetExecutorEsl() const
    {
        IAM_LOGI("start");
        return ESL0;
    }

    std::vector<uint8_t> GetExecutorPublicKey() const
    {
        IAM_LOGI("start");
        return {};
    }

    std::string GetExecutorDeviceUdid() const
    {
        IAM_LOGI("start");
        return "";
    }

    int32_t BeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(publicKey);
        static_cast<void>(command);
        return SUCCESS;
    }

    int32_t EndExecute(uint64_t scheduleId, const Attributes &command)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(command);
        return SUCCESS;
    }

    int32_t SetProperty(const Attributes &properties)
    {
        IAM_LOGI("start");
        static_cast<void>(properties);
        return SUCCESS;
    }

    int32_t GetProperty(const Attributes &condition, Attributes &values)
    {
        IAM_LOGI("start");
        static_cast<void>(condition);
        static_cast<void>(values);
        return SUCCESS;
    }

    int32_t SendData(uint64_t scheduleId, const Attributes &data)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(data);
        return SUCCESS;
    }

    void DeleteFromDriver()
    {
        IAM_LOGI("start");
    }

    void DetachFromDriver()
    {
        IAM_LOGI("start");
    }
};

class DummyResourceNodePoolListener final : public ResourceNodePool::ResourceNodePoolListener {
public:
    void OnResourceNodePoolInsert(const std::shared_ptr<ResourceNode> &resource)
    {
        IAM_LOGI("start");
        static_cast<void>(resource);
    }

    void OnResourceNodePoolDelete(const std::shared_ptr<ResourceNode> &resource)
    {
        IAM_LOGI("start");
        static_cast<void>(resource);
    }

    void OnResourceNodePoolUpdate(const std::shared_ptr<ResourceNode> &resource)
    {
        IAM_LOGI("start");
        static_cast<void>(resource);
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // COMMON_DUMMY_H

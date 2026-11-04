/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef IAM_DELETION_H
#define IAM_DELETION_H

#include <cstdint>
#include <memory>
#include <optional>

#include "credential_info_interface.h"
#include "update_pin_param_interface.h"
#include "user_auth_engine_types.h"
#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Deletion {
public:
    struct DeleteParam {
        int32_t userId {0};
        uint64_t credentialId {0};
        uint32_t tokenId {0};
        std::string callerName;
        int32_t callerType {-1};
        std::vector<uint8_t> token;
    };

    virtual ~Deletion() = default;

    virtual bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        std::shared_ptr<ScheduleNodeCallback> callback, bool &isStartSchedule,
        std::vector<EngCredentialInfo> &credentialInfos) = 0;
    virtual bool Update(const std::vector<uint8_t> &scheduleResult,
        std::shared_ptr<CredentialInfoInterface> &info) = 0;
    virtual bool Cancel() = 0;

    virtual void SetAccessTokenId(uint32_t tokenId) = 0;
    virtual uint32_t GetAccessTokenId() const = 0;
    virtual int32_t GetLatestError() const = 0;
    virtual int32_t GetUserId() const = 0;

protected:
    virtual void SetLatestError(int32_t error) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_DELETION_H
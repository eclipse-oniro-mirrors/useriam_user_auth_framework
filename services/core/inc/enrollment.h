/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef IAM_ENROLLMENT_H
#define IAM_ENROLLMENT_H

#include <cstdint>
#include <memory>
#include <optional>

#include "credential_info_interface.h"
#include "update_pin_param_interface.h"
#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Enrollment {
public:
    struct EnrollmentPara {
        int32_t userId {0};
        AuthType authType {ALL};
        PinSubType pinType {PIN_SIX};
        bool isUpdate {false};
        uint32_t tokenId {0};
        std::vector<uint8_t> token;
        std::string callerName;
        int32_t sdkVersion;
        int32_t callerType;
        std::string additionalInfo;
        bool isRestore {false};
        std::vector<uint8_t> restoreData;
    };

    virtual ~Enrollment() = default;

    virtual void SetExecutorSensorHint(uint32_t executorSensorHint) = 0;
    virtual void SetAuthToken(const std::vector<uint8_t> &authToken) = 0;
    virtual void SetAccessTokenId(uint32_t tokenId) = 0;
    virtual void SetPinSubType(PinSubType pinSubType) = 0;
    virtual void SetIsUpdate(bool isUpdate) = 0;
    virtual bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        std::shared_ptr<ScheduleNodeCallback> callback) = 0;
    virtual bool Update(const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
        std::shared_ptr<CredentialInfoInterface> &info, std::shared_ptr<UpdatePinParamInterface> &pinInfo,
        std::optional<uint64_t> &secUserId) = 0;
    virtual bool Cancel() = 0;
    virtual uint32_t GetAccessTokenId() const = 0;
    virtual int32_t GetLatestError() const = 0;
    virtual int32_t GetUserId() const = 0;
    virtual std::vector<uint8_t> GetRestoreData() const = 0;

protected:
    virtual void SetLatestError(int32_t error) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_ENROLLMENT_H
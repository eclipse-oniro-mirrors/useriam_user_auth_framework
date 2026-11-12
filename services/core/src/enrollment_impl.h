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

#ifndef IAM_ENROLLMENT_IMPL_H
#define IAM_ENROLLMENT_IMPL_H

#include <cstdint>
#include <memory>

#include "enrollment.h"
#include "schedule_node.h"
#include "user_auth_engine_types.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EnrollmentImpl final : public Enrollment, public NoCopyable {
public:
    explicit EnrollmentImpl(EnrollmentPara enrollPara);
    ~EnrollmentImpl() override;

    void SetExecutorSensorHint(uint32_t executorSensorHint) override;
    void SetAuthToken(const std::vector<uint8_t> &authToken) override;
    void SetAccessTokenId(uint32_t tokenId) override;
    void SetPinSubType(PinSubType pinSubType) override;
    void SetIsUpdate(bool isUpdate) override;

    bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        std::shared_ptr<ScheduleNodeCallback> callback) override;
    bool Update(const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
        std::shared_ptr<CredentialInfoInterface> &info, std::shared_ptr<UpdatePinParamInterface> &pinInfo,
        std::optional<uint64_t> &secUserId) override;
    bool Cancel() override;
    uint32_t GetAccessTokenId() const override;
    int32_t GetLatestError() const override;
    int32_t GetUserId() const override;
    std::vector<uint8_t> GetRestoreData() const override;

protected:
    void SetLatestError(int32_t error) override;

private:
    bool GetSecUserId(std::optional<uint64_t> &secUserId);
    bool StartSchedule(int32_t userId, EngScheduleInfo &info,
        std::vector<std::shared_ptr<ScheduleNode>> &scheduleList, std::shared_ptr<ScheduleNodeCallback> callback);

    EnrollmentPara enrollPara_;
    std::vector<uint8_t> authToken_;
    std::optional<uint64_t> secUserId_ {std::nullopt};

    uint32_t executorSensorHint_ {0};
    uint32_t tokenId_ {0};
    uint64_t scheduleId_ {0};
    PinSubType pinSubType_ {PinSubType::PIN_MAX};
    bool isUpdate_ {false};
    bool running_ {false};
    int32_t latestError_ = ResultCode::GENERAL_ERROR;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_ENROLLMENT_IMPL_H
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
#ifndef IAM_MOCK_ENROLLMENT_H
#define IAM_MOCK_ENROLLMENT_H

#include <gmock/gmock.h>

#include "enrollment.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockEnrollment final : public Enrollment {
public:
    virtual ~MockEnrollment() = default;
    MOCK_METHOD1(SetExecutorSensorHint, void(uint32_t executorSensorHint));
    MOCK_METHOD1(SetAuthToken, void(const std::vector<uint8_t> &authToken));
    MOCK_METHOD1(SetAccessTokenId, void(uint32_t tokenId));
    MOCK_METHOD1(SetPinSubType, void(PinSubType pinSubType));
    MOCK_METHOD1(SetIsUpdate, void(bool isUpdate));
    MOCK_METHOD2(Start,
        bool(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList, std::shared_ptr<ScheduleNodeCallback> callback));
    MOCK_METHOD5(Update, bool(const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
                            std::shared_ptr<CredentialInfoInterface> &info,
                            std::shared_ptr<UpdatePinParamInterface> &pinInfo,
                            std::optional<uint64_t> &secUserId));
    MOCK_METHOD0(Cancel, bool());
    MOCK_CONST_METHOD0(GetAccessTokenId, uint32_t());
    MOCK_CONST_METHOD0(GetLatestError, int32_t());
    MOCK_CONST_METHOD0(GetUserId, int32_t());
    MOCK_CONST_METHOD0(GetRestoreData, std::vector<uint8_t>());

protected:
    MOCK_METHOD1(SetLatestError, void(int32_t error));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_ENROLLMENT_H
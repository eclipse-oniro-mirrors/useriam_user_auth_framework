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

#ifndef IAM_AUTHENTICATION_IMPL_H
#define IAM_AUTHENTICATION_IMPL_H

#include <atomic>
#include <cstdint>
#include <memory>

#include "authentication.h"
#include "schedule_node.h"
#include "user_auth_engine_types.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthenticationImpl final : public Authentication, public NoCopyable {
public:
    AuthenticationImpl(uint64_t contextId, const AuthenticationPara &authPara);
    ~AuthenticationImpl() override;

    void SetExecutor(uint32_t executorIndex) override;
    void SetChallenge(const std::vector<uint8_t> &challenge) override;
    void SetAccessTokenId(uint32_t tokenId) override;
    void SetEndAfterFirstFail(bool endAfterFirstFail) override;
    void SetCollectorUdid(std::string &collectorUdid) override;

    bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        AcquireInfoCallback &acquireInfoCallback,
        std::shared_ptr<ScheduleNodeCallback> callback) override;
    bool Update(const std::vector<uint8_t> &scheduleResult, AuthResultInfo &resultInfo,
        AcquireInfoCallback &acquireInfoCallback) override;
    std::vector<Authentication::AuthExecutorMsg> GetAuthExecutorMsgs() const override;
    bool Cancel() override;
    uint32_t GetAccessTokenId() const override;
    int32_t GetLatestError() const override;
    int32_t GetUserId() const override;
    int32_t GetAuthType() const override;

protected:
    void SetLatestError(int32_t error) override;

private:
    bool GetAuthParam(EngAuthParamExt &param);
    uint64_t contextId_;
    AuthenticationPara authPara_;
    bool endAfterFirstFail_ {false};

    uint32_t executorSensorHint_ {0};
    uint32_t executorIndex_ {0};
    std::vector<uint8_t> challenge_ {};
    uint32_t tokenId_ {0};

    std::atomic<bool> running_ {false};

    int32_t latestError_ = ResultCode::GENERAL_ERROR;
    std::vector<Authentication::AuthExecutorMsg> authExecutorMsgs_ {};
    std::string collectorUdid_ {};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_AUTHENTICATION_IMPL_H
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

#ifndef IAM_DELETE_IMPL_H
#define IAM_DELETE_IMPL_H

#include <cstdint>
#include <memory>

#include "deletion.h"
#include "schedule_node.h"
#include "user_auth_engine_types.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class DeleteImpl final : public Deletion, public NoCopyable {
public:
    explicit DeleteImpl(DeleteParam deletePara);
    ~DeleteImpl() override;

    bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        std::shared_ptr<ScheduleNodeCallback> callback, bool &isCredentialDelete,
        std::vector<EngCredentialInfo> &credentialInfos) override;
    bool Update(const std::vector<uint8_t> &scheduleResult, std::shared_ptr<CredentialInfoInterface> &info) override;
    bool Cancel() override;

    void SetAccessTokenId(uint32_t tokenId) override;
    uint32_t GetAccessTokenId() const override;
    int32_t GetLatestError() const override;
    int32_t GetUserId() const override;

protected:
    void SetLatestError(int32_t error) override;

private:
    bool StartSchedule(int32_t userId, EngScheduleInfo &info,
        std::vector<std::shared_ptr<ScheduleNode>> &scheduleList, std::shared_ptr<ScheduleNodeCallback> callback);
    bool DeleteCredential(int32_t userId, std::vector<EngCredentialInfo> &credentialInfo);
    bool HandlePinUpdate();

    DeleteParam deletePara_;

    uint32_t tokenId_ {0};
    uint64_t scheduleId_ {0};
    int32_t latestError_ = ResultCode::GENERAL_ERROR;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_DELETE_IMPL_H
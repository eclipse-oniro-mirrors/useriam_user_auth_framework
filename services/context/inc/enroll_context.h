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

#ifndef IAM_ENROLL_CONTEXT_H
#define IAM_ENROLL_CONTEXT_H

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "base_context.h"
#include "enrollment.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EnrollContext : public BaseContext {
public:
    EnrollContext(uint64_t contextId, std::shared_ptr<Enrollment> enroll, bool needSubscribeAppState,
        std::shared_ptr<ContextCallback> callback);
    ~EnrollContext() override = default;
    ContextType GetContextType() const override;
    uint32_t GetTokenId() const override;
    int32_t GetUserId() const override;

protected:
    bool OnStart() override;
    void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr) override;
    bool OnStop() override;

private:
    bool SendRestoreCommand(const std::shared_ptr<ScheduleNode> &scheduleNode);
    bool UpdateScheduleResult(const std::shared_ptr<Attributes> &scheduleResultAttr, uint64_t &credentialId,
        std::shared_ptr<UpdatePinParamInterface> &pinInfo, std::optional<uint64_t> &secUserId);
    void InvokeResultCallback(int32_t resultCode, const uint64_t credentialId,
        const std::shared_ptr<UpdatePinParamInterface> &pinInfo, std::optional<uint64_t> &secUserId) const;
    std::shared_ptr<Enrollment> enroll_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_ENROLL_CONTEXT_H
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

#ifndef SCHEDULE_HOLDER_CONTEXT_H
#define SCHEDULE_HOLDER_CONTEXT_H

#include <cstdint>
#include <memory>

#include "nocopyable.h"

#include "authentication_impl.h"
#include "base_context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ScheduleHolderContext : public Context,
                              public std::enable_shared_from_this<ScheduleHolderContext>,
                              public NoCopyable {
public:
    ScheduleHolderContext(uint64_t contextId, std::shared_ptr<ScheduleNode> scheduleNode);
    ~ScheduleHolderContext() override = default;

    bool Start() override;
    bool Stop() override;
    uint64_t GetContextId() const override;
    ContextType GetContextType() const override;
    std::shared_ptr<ScheduleNode> GetScheduleNode(uint64_t scheduleId) const override;
    uint32_t GetTokenId() const override;
    int32_t GetLatestError() const override;
    int32_t GetUserId() const override;
    int32_t GetAuthType() const override;
    std::string GetCallerName() const override;
    void SetRemoteAuthParam(const WidgetParamInner &widgetParam, const sptr<IModalCallback> &modalCallback) override;

protected:
    void SetLatestError(int32_t error) override;

private:
    uint64_t contextId_ = INVALID_CONTEXT_ID;
    std::shared_ptr<ScheduleNode> scheduleNode_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // SCHEDULE_HOLDER_CONTEXT_H
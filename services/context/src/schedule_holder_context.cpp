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
#include "schedule_holder_context.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_FILE_ID LOG_FILE_SCHEDULE_HOLDER_CONTEXT
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ScheduleHolderContext::ScheduleHolderContext(uint64_t contextId, std::shared_ptr<ScheduleNode> scheduleNode)
    : contextId_(contextId),
      scheduleNode_(scheduleNode)
{
}

bool ScheduleHolderContext::Start()
{
    IAM_LOGE("not implemented");
    return false;
}

bool ScheduleHolderContext::Stop()
{
    IAM_LOGE("not implemented");
    return false;
}

uint64_t ScheduleHolderContext::GetContextId() const
{
    return contextId_;
}

ContextType ScheduleHolderContext::GetContextType() const
{
    return ContextType::SCHEDULE_HOLDER_CONTEXT;
}

int32_t ScheduleHolderContext::GetAuthType() const
{
    IAM_LOGE("not implemented");
    return 0;
}

std::string ScheduleHolderContext::GetCallerName() const
{
    IAM_LOGE("not implemented");
    return "";
}

std::shared_ptr<ScheduleNode> ScheduleHolderContext::GetScheduleNode(uint64_t scheduleId) const
{
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleNode_ != nullptr, nullptr);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleNode_->GetScheduleId() == scheduleId, nullptr);

    return scheduleNode_;
}

uint32_t ScheduleHolderContext::GetTokenId() const
{
    IAM_LOGE("not implemented");
    return 0;
}

int32_t ScheduleHolderContext::GetLatestError() const
{
    IAM_LOGE("not implemented");
    return 0;
}

int32_t ScheduleHolderContext::GetUserId() const
{
    IAM_LOGE("not implemented");
    return 0;
}

void ScheduleHolderContext::SetLatestError(int32_t error)
{
    static_cast<void>(error);
    IAM_LOGE("not implemented");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

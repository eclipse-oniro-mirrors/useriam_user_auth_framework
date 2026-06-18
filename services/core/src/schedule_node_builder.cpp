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
#include "schedule_node_builder.h"

#include <mutex>

#include "nocopyable.h"

#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_FILE_ID LOG_FILE_SCHEDULE_NODE_BUILDER
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using Builder = ScheduleNode::Builder;

ScheduleNodeBuilder::ScheduleNodeBuilder(const std::shared_ptr<ResourceNode> &collector,
    const std::shared_ptr<ResourceNode> &verifier)
    : collector_(collector),
      verifier_(verifier)
{
    if (collector) {
        info_.authType = collector->GetAuthType();
    }
    info_.endAfterFirstFail = false;
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetScheduleId(uint64_t scheduleId)
{
    info_.scheduleId = scheduleId;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetAccessTokenId(uint32_t tokenId)
{
    info_.tokenId = tokenId;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetCollectorTokenId(uint32_t collectorTokenId)
{
    info_.collectorTokenId = collectorTokenId;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetPinSubType(PinSubType pinSubType)
{
    info_.pinSubType = pinSubType;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetTemplateIdList(const std::vector<uint64_t> &templateIdList)
{
    info_.templateIdList = templateIdList;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetAuthType(AuthType authType)
{
    info_.authType = authType;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetExecutorMatcher(uint32_t executorMatcher)
{
    info_.executorMatcher = executorMatcher;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetScheduleMode(ScheduleMode scheduleMode)
{
    info_.scheduleMode = scheduleMode;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetScheduleCallback(const std::shared_ptr<ScheduleNodeCallback> &callback)
{
    info_.callback = callback;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetExpiredTime(uint32_t ms)
{
    info_.expiredTime = ms;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetThreadHandler(const std::shared_ptr<ThreadHandler> &threadHandler)
{
    info_.threadHandler = threadHandler;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetEndAfterFirstFail(const bool endAfterFirstFail)
{
    info_.endAfterFirstFail = endAfterFirstFail;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetCollectorMessage(const std::vector<uint8_t> &message)
{
    info_.collectorMessage = message;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetVerifierMessage(const std::vector<uint8_t> &message)
{
    info_.verifierMessage = message;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetAuthIntent(int32_t authIntent)
{
    info_.authIntent = authIntent;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetUserId(int32_t userId)
{
    info_.userId = userId;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetAdditionalInfo(const std::string &additionalInfo)
{
    info_.additionalInfo = additionalInfo;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetTitle(const std::string &title)
{
    info_.title = title;
    return shared_from_this();
}

std::shared_ptr<Builder> ScheduleNodeBuilder::SetAuthScene(AuthScene authScene)
{
    info_.authScene = authScene;
    return shared_from_this();
}

std::shared_ptr<ScheduleNode> ScheduleNodeBuilder::Build()
{
    if (!CheckParameters()) {
        IAM_LOGE("checkParameters error");
        return nullptr;
    }
    IAM_LOGD("scheduleNode builder start to build");
    info_.collector = collector_;
    info_.verifier = verifier_;
    return Common::MakeShared<ScheduleNodeImpl>(info_);
}

bool ScheduleNodeBuilder::CheckParameters() const
{
    if (collector_ && collector_->GetAuthType() != info_.authType) {
        IAM_LOGE("authType mismatch");
        return false;
    }
    return true;
}

bool ScheduleNodeBuilder::CheckExecutors(const std::shared_ptr<ResourceNode> &collector,
    const std::shared_ptr<ResourceNode> &verifier)
{
    if (!collector) {
        IAM_LOGE("collector not set");
        return false;
    }

    if (!verifier) {
        IAM_LOGE("verifier not set");
        return false;
    }

    if (collector->GetAuthType() != verifier->GetAuthType()) {
        IAM_LOGE("collector_ && verifier authType mismatch");
        return false;
    }

    if (collector->GetExecutorMatcher() != verifier->GetExecutorMatcher()) {
        IAM_LOGE("executorType mismatch");
        return false;
    }

    // all in one
    if (collector == verifier && collector->GetExecutorRole() == ALL_IN_ONE) {
        return true;
    }

    if (collector->GetExecutorRole() == COLLECTOR && verifier->GetExecutorRole() == VERIFIER) {
        return true;
    }

    IAM_LOGE("executor role type mismatch");
    return false;
}

std::shared_ptr<Builder> Builder::New(const std::shared_ptr<ResourceNode> &collector,
    const std::shared_ptr<ResourceNode> &verifier)
{
    auto result = ScheduleNodeBuilder::CheckExecutors(collector, verifier);
    if (!result) {
        IAM_LOGE("checkExecutors failed");
        return nullptr;
    }

    return Common::MakeShared<ScheduleNodeBuilder>(collector, verifier);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

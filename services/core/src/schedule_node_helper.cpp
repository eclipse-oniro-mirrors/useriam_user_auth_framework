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
#include "schedule_node_helper.h"

#include <cinttypes>

#include "iam_check.h"
#include "iam_logger.h"
#include "resource_node_pool.h"

#define LOG_FILE_ID LOG_FILE_SCHEDULE_NODE_HELPER
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
bool ScheduleNodeHelper::BuildFromHdi(const std::vector<HdiScheduleInfo> &infos,
    std::shared_ptr<ScheduleNodeCallback> callback, std::vector<std::shared_ptr<ScheduleNode>> &nodes)
{
    NodeOptionalPara para;
    return BuildFromHdi(infos, callback, nodes, para);
}

bool ScheduleNodeHelper::BuildFromHdi(const std::vector<HdiScheduleInfo> &infos,
    std::shared_ptr<ScheduleNodeCallback> callback, std::vector<std::shared_ptr<ScheduleNode>> &nodes,
    const NodeOptionalPara &para)
{
    std::vector<std::shared_ptr<ScheduleNode>> outputs;

    for (const auto &info : infos) {
        std::shared_ptr<ScheduleNode> node;
        if (!ScheduleInfoToScheduleNode(info, node, para, callback)) {
            IAM_LOGE("ScheduleInfoToScheduleNode error");
            return false;
        }
        outputs.push_back(node);
    }

    nodes.swap(outputs);
    return true;
}

bool ScheduleNodeHelper::ScheduleInfoToScheduleNode(const HdiScheduleInfo &info, std::shared_ptr<ScheduleNode> &node,
    const NodeOptionalPara &para, const std::shared_ptr<ScheduleNodeCallback> &callback)
{
    if (info.executorIndexes.empty()) {
        IAM_LOGE("executors empty");
        return false;
    }
    std::shared_ptr<ResourceNode> collector;
    std::shared_ptr<ResourceNode> verifier;

    std::vector<uint8_t> collectorMessage;
    std::vector<uint8_t> verifierMessage;
    if (!ScheduleInfoToExecutors(info, collector, verifier, collectorMessage, verifierMessage)) {
        IAM_LOGE("ScheduleInfoToExecutors error");
        return false;
    }

    IAM_LOGD("collectorMessage size: %{public}zu, verifierMessage size %{public}zu",
        collectorMessage.size(), verifierMessage.size());

    auto builder = ScheduleNode::Builder::New(collector, verifier);
    if (builder == nullptr) {
        IAM_LOGE("invalid builder");
        return false;
    }

    if (para.tokenId.has_value()) {
        builder->SetAccessTokenId(para.tokenId.value());
    }

    node = builder->SetAuthType(static_cast<AuthType>(info.authType))
        ->SetExecutorMatcher(info.executorMatcher)
        ->SetScheduleId(info.scheduleId)
        ->SetTemplateIdList(info.templateIds)
        ->SetScheduleMode(static_cast<ScheduleMode>(info.scheduleMode))
        ->SetExpiredTime(para.expire.value_or(0))
        ->SetPinSubType(para.pinSubType.value_or(PinSubType::PIN_MAX))
        ->SetScheduleCallback(callback)
        ->SetEndAfterFirstFail(para.endAfterFirstFail.value_or(false))
        ->SetCollectorTokenId(para.collectorTokenId)
        ->SetCollectorMessage(collectorMessage)
        ->SetVerifierMessage(verifierMessage)
        ->SetAuthIntent(para.authIntent)
        ->SetUserId(para.userId)
        ->SetAdditionalInfo(para.additionalInfo)
        ->SetTitle(para.title)
        ->SetAuthScene(para.authScene)
        ->Build();
    if (node == nullptr) {
        IAM_LOGE("builder failed");
        return false;
    }
    return true;
}

bool ScheduleNodeHelper::ScheduleInfoToExecutors(const HdiScheduleInfo &info, std::shared_ptr<ResourceNode> &collector,
    std::shared_ptr<ResourceNode> &verifier, std::vector<uint8_t> &collectorMessage,
    std::vector<uint8_t> &verifierMessage)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(info.executorIndexes.size() == info.executorMessages.size(), false);
    IF_FALSE_LOGE_AND_RETURN_VAL(info.executorIndexes.size() > 0, false);

    for (uint32_t i = 0; i < info.executorIndexes.size(); i++) {
        uint64_t executorIndex = info.executorIndexes[i];
        auto resource = ResourceNodePool::Instance().Select(executorIndex).lock();
        if (resource == nullptr) {
            IAM_LOGE("invalid executorId ****%{public}hx", static_cast<uint16_t>(executorIndex));
            return false;
        }
        IAM_LOGI("executor role %{public}d", resource->GetExecutorRole());
        switch (resource->GetExecutorRole()) {
            case COLLECTOR: {
                collector = resource;
                collectorMessage = info.executorMessages[i];
                break;
            }
            case VERIFIER: {
                verifier = resource;
                verifierMessage = info.executorMessages[i];
                break;
            }
            case ALL_IN_ONE: {
                collector = resource;
                verifier = resource;
                verifierMessage = info.executorMessages[i];
                break;
            }
            default: {
                IAM_LOGE("invalid executor role");
                break;
            }
        }
    }
    if (collector == nullptr) {
        IAM_LOGE("invalid executor collector");
        return false;
    }
    if (verifier == nullptr) {
        IAM_LOGE("invalid executor verifier");
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
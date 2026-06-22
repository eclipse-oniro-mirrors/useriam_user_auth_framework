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
#include "schedule_resource_node_listener.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SCHEDULE_RESOURCE_NODE_LISTENER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ScheduleResourceNodeListener::ScheduleResourceNodeListener(std::weak_ptr<ScheduleNode> weakNode):  weakNode_(weakNode)
{}

void ScheduleResourceNodeListener::OnResourceNodePoolInsert(const std::shared_ptr<ResourceNode> &resource)
{}

void ScheduleResourceNodeListener::OnResourceNodePoolDelete(const std::shared_ptr<ResourceNode> &resource)
{
    IF_FALSE_LOGE_AND_RETURN(resource != nullptr);

    auto scheduleNode = weakNode_.lock();
    IF_FALSE_LOGE_AND_RETURN(scheduleNode != nullptr);

    auto collector = scheduleNode->GetCollectorExecutor().lock();
    auto verifier = scheduleNode->GetVerifyExecutor().lock();
    if (collector == resource || verifier == resource) {
        IAM_LOGI("resource node is deleted, stop schedule");
        scheduleNode->StopSchedule(GENERAL_ERROR);
    }
}

void ScheduleResourceNodeListener::OnResourceNodePoolUpdate(const std::shared_ptr<ResourceNode> &resource)
{}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

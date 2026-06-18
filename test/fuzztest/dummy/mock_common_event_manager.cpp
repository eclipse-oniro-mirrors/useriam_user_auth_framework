/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "common_event_manager.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_PUBLISH_EVENT_ADAPTER

namespace OHOS {
namespace EventFwk {

bool CommonEventManager::PublishCommonEvent(const CommonEventData &data)
{
    IAM_LOGI("start.");
    return true;
}

bool CommonEventManager::SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
{
    IAM_LOGI("start.");
    return true;
}

int32_t CommonEventManager::NewSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
{
    IAM_LOGI("start.");
    return 0;
}

bool CommonEventManager::UnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
{
    IAM_LOGI("start.");
    return true;
}

int32_t CommonEventManager::NewUnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
{
    IAM_LOGI("start.");
    return 0;
}

}  // namespace EventFwk
}  // namespace OHOS
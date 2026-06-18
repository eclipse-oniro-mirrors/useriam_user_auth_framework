/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "executor_messenger_service.h"

#include <cinttypes>

#include "iam_logger.h"
#include "iam_common_defines.h"
#include "iam_ptr.h"

#define LOG_FILE_ID LOG_FILE_EXECUTOR_MESSENGER_SERVICE
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ExecutorMessengerService::ExecutorMessengerService()
{
    IAM_LOGI("ExecutorMessengerService init");
}

sptr<ExecutorMessengerService> ExecutorMessengerService::GetInstance()
{
    static sptr<ExecutorMessengerService> instance(new (std::nothrow) ExecutorMessengerService());
    if (instance == nullptr) {
        IAM_LOGE("instance is nullptr");
    }
    return instance;
}

int32_t ExecutorMessengerService::SendData(uint64_t scheduleId, int32_t dstRole, const std::vector<uint8_t> &msg)
{
    IAM_LOGI("start");
    auto scheduleNode = ContextPool::Instance().SelectScheduleNodeByScheduleId(scheduleId);
    if (scheduleNode == nullptr) {
        IAM_LOGE("selected schedule node is nullptr");
        return GENERAL_ERROR;
    }
    bool result = scheduleNode->SendMessage(static_cast<ExecutorRole>(dstRole), msg);
    if (!result) {
        IAM_LOGE("continue schedule failed");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t ExecutorMessengerService::Finish(uint64_t scheduleId, int32_t resultCode,
    const std::vector<uint8_t> &finalResult)
{
    IAM_LOGI("start");
    auto scheduleNode = ContextPool::Instance().SelectScheduleNodeByScheduleId(scheduleId);
    if (scheduleNode == nullptr) {
        IAM_LOGE("selected schedule node is nullptr");
        return GENERAL_ERROR;
    }

    auto attributes = Common::MakeShared<Attributes>(finalResult);
    if (attributes == nullptr) {
        IAM_LOGE("failed to create attributes");
        return GENERAL_ERROR;
    }

    bool result = scheduleNode->ContinueSchedule(static_cast<ResultCode>(resultCode), attributes);
    if (!result) {
        IAM_LOGE("continue schedule failed");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t ExecutorMessengerService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t ExecutorMessengerService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
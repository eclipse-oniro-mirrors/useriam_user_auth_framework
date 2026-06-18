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

#include "executor_callback_service.h"

#include "executor_messenger_client.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_FILE_ID LOG_FILE_EXECUTOR_CALLBACK_SERVICE
#define LOG_TAG "AUTH_EXECUTOR_MGR_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ExecutorCallbackService::ExecutorCallbackService(const std::shared_ptr<ExecutorRegisterCallback> &impl)
    : callback_(impl)
{
}

int32_t ExecutorCallbackService::OnMessengerReady(const sptr<IExecutorMessenger> &messenger,
    const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGD("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    auto wrapper = Common::MakeShared<ExecutorMessengerClient>(messenger);
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }
    callback_->OnMessengerReady(wrapper, publicKey, templateIdList);
    return SUCCESS;
}

int32_t ExecutorCallbackService::OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
    const std::vector<uint8_t> &command)
{
    IAM_LOGD("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes attributes(command);
    return callback_->OnBeginExecute(scheduleId, publicKey, attributes);
}

int32_t ExecutorCallbackService::OnEndExecute(uint64_t scheduleId, const std::vector<uint8_t> &command)
{
    IAM_LOGD("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes attributes(command);
    return callback_->OnEndExecute(scheduleId, attributes);
}

int32_t ExecutorCallbackService::OnSetProperty(const std::vector<uint8_t> &properties)
{
    IAM_LOGD("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes attributes(properties);
    return callback_->OnSetProperty(attributes);
}

int32_t ExecutorCallbackService::OnGetProperty(const std::vector<uint8_t> &condition, std::vector<uint8_t> &values)
{
    IAM_LOGD("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes conditionAttr(condition);
    Attributes valuesAttr;
    auto ret = callback_->OnGetProperty(conditionAttr, valuesAttr);
    if (ret == SUCCESS) {
        values = valuesAttr.Serialize();
    }
    return ret;
}

int32_t ExecutorCallbackService::OnSendData(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGD("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes attributes(extraInfo);
    return callback_->OnSendData(scheduleId, attributes);
}

int32_t ExecutorCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t ExecutorCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
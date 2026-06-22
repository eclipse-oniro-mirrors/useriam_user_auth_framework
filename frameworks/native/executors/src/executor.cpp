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

#include "executor.h"

#include <sstream>

#include "framework_executor_callback.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_EXECUTOR

namespace OHOS {
namespace UserIam {
namespace UserAuth {
Executor::Executor(std::shared_ptr<ExecutorMgrWrapper> executorMgrWrapper,
    std::shared_ptr<IAuthExecutorHdi> executorHdi, uint16_t hdiId)
    : executorMgrWrapper_(executorMgrWrapper),
      executorHdi_(executorHdi),
      hdiId_(hdiId)
{
    auto hdi = executorHdi_;
    IF_FALSE_LOGE_AND_RETURN(hdi != nullptr);
    ExecutorInfo executorInfo = {};
    IF_FALSE_LOGE_AND_RETURN(hdi->GetExecutorInfo(executorInfo) == ResultCode::SUCCESS);
    authType_ = executorInfo.authType;
    executorRole_ = executorInfo.executorRole;
    std::ostringstream ss;
    uint32_t combineExecutorId =
        Common::CombineUint16ToUint32(hdiId_, static_cast<uint16_t>(executorInfo.executorSensorHint));
    const uint32_t uint32HexWidth = 8;
    ss << "Executor(Id:0x" << std::setfill('0') << std::setw(uint32HexWidth) << std::hex << combineExecutorId
        << ", role:" << executorRole_ << ", authType:" << authType_ << ")";
    description_ = ss.str();
}

void Executor::OnHdiDisconnect()
{
    IAM_LOGI("%{public}s start", GetDescription());
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        executorHdi_ = nullptr;
    }
    RespondCallbackOnDisconnect();
    UnregisterExecutorCallback();
}

void Executor::Register()
{
    IAM_LOGI("%{public}s start", GetDescription());
    ExecutorInfo executorInfo = {};
    auto hdi = GetExecutorHdi();
    if (hdi == nullptr) {
        IAM_LOGE("executorHdi_ is disconnected, skip framework ready process");
        return;
    }
    ResultCode ret = hdi->GetExecutorInfo(executorInfo);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("Get executor info failed");
        return;
    }
    RegisterExecutorCallback(executorInfo);
}

void Executor::RegisterExecutorCallback(ExecutorInfo &executorInfo)
{
    IAM_LOGI("%{public}s start", GetDescription());
    std::lock_guard<std::recursive_mutex> lockRegister(registerMutex_);
    uint32_t combineExecutorId =
        Common::CombineUint16ToUint32(hdiId_, static_cast<uint16_t>(executorInfo.executorSensorHint));
    executorInfo.executorSensorHint = combineExecutorId;
    std::shared_ptr<ExecutorRegisterCallback> executorCallback = nullptr;
    bool isExecutorRegistered = false;
    {
        std::lock_guard<std::recursive_mutex> lockCallback(mutex_);
        if (executorCallback_ == nullptr) {
            executorCallback_ = Common::MakeShared<FrameworkExecutorCallback>(weak_from_this());
            IF_FALSE_LOGE_AND_RETURN(executorCallback_ != nullptr);
        }
        executorCallback = executorCallback_;

        if (executorIndex_.has_value()) {
            isExecutorRegistered = true;
        }
    }
    if (isExecutorRegistered) {
        IAM_LOGI("%{public}s executor already registered, try unregister", GetDescription());
        UnregisterExecutorCallback();
    }
    IF_FALSE_LOGE_AND_RETURN(executorMgrWrapper_ != nullptr);
    uint64_t executorIndex = executorMgrWrapper_->Register(executorInfo, executorCallback);
    IF_FALSE_LOGE_AND_RETURN(executorIndex != INVALID_EXECUTOR_INDEX);
    {
        std::lock_guard<std::recursive_mutex> lockExecutorIndex(mutex_);
        executorIndex_ = executorIndex;
    }
    IAM_LOGI("%{public}s register executor callback ok, executor index %{public}s", GetDescription(),
        GET_MASKED_STRING(executorIndex).c_str());
}

void Executor::UnregisterExecutorCallback()
{
    IAM_LOGI("%{public}s start", GetDescription());
    std::lock_guard<std::recursive_mutex> lockRegister(registerMutex_);
    uint64_t executorIndex = 0;
    {
        std::lock_guard<std::recursive_mutex> lockExecutorIndex(mutex_);
        if (!executorIndex_.has_value()) {
            IAM_LOGI("not registered, no need unregister");
            return;
        }
        executorIndex = executorIndex_.value();
        executorIndex_ = std::nullopt;
    }

    IF_FALSE_LOGE_AND_RETURN(executorMgrWrapper_ != nullptr);
    executorMgrWrapper_->Unregister(executorIndex);
    IAM_LOGI("%{public}s unregister executor callback ok, executor index %{public}s", GetDescription(),
        GET_MASKED_STRING(executorIndex).c_str());
}

void Executor::AddCommand(std::shared_ptr<IAsyncCommand> command)
{
    IAM_LOGD("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(command != nullptr);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    command2Respond_.insert(command);
}

void Executor::RemoveCommand(std::shared_ptr<IAsyncCommand> command)
{
    IAM_LOGD("%{public}s start", GetDescription());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    command2Respond_.erase(command);
}

void Executor::RespondCallbackOnDisconnect()
{
    IAM_LOGI("%{public}s start", GetDescription());
    std::set<std::shared_ptr<IAsyncCommand>> command2NotifyOnHdiDisconnect;
    {
        // cmd->OnHdiDisconnect will invoke RemoveCommand thus modify command2Respond_, make a copy before call
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        command2NotifyOnHdiDisconnect =
            std::set<std::shared_ptr<IAsyncCommand>>(command2Respond_.begin(), command2Respond_.end());
    }

    for (const auto &cmd : command2NotifyOnHdiDisconnect) {
        if (cmd == nullptr) {
            IAM_LOGE("cmd is null");
            continue;
        }
        cmd->OnHdiDisconnect();
    }
    IAM_LOGI("success");
}

std::shared_ptr<IAuthExecutorHdi> Executor::GetExecutorHdi()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return executorHdi_;
}

const char *Executor::GetDescription()
{
    return description_.c_str();
}

int32_t Executor::GetAuthType() const
{
    return authType_;
}

int32_t Executor::GetExecutorRole() const
{
    return executorRole_;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

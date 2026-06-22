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
#include "ipc_client_utils.h"

#include <exception>
#include <future>

#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iservice_registry.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_IPC_CLIENT_UTILS

namespace OHOS {
namespace UserIam {
namespace UserAuth {
sptr<IRemoteObject> IpcClientUtils::GetRemoteObject(int32_t saId)
{
    sptr<IRemoteObject> obj(nullptr);
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!sam) {
        IAM_LOGE("failed to get system ability manager");
        return obj;
    }

    obj = sam->CheckSystemAbility(saId);
    if (!obj) {
        IAM_LOGE("failed to get service");
        return obj;
    }
    return obj;
}

int32_t IpcClientUtils::RunOnResidentSync(std::function<int32_t()> func, uint32_t timeoutSec)
{
    IAM_LOGI("start");
    auto resultPromise = std::make_shared<std::promise<int32_t>>();
    if (resultPromise == nullptr) {
        IAM_LOGE("resultPromise is nullptr");
        return GENERAL_ERROR;
    }

    auto future = resultPromise->get_future();
    std::thread([taskFunc = std::move(func), promise = resultPromise]() mutable {
        try {
            promise->set_value(taskFunc());
        } catch (...) {
            try {
                promise->set_exception(std::current_exception());
            } catch (...) {
                IAM_LOGE("RunOnResidentSync set_exception failed");
            }
        }
    }).detach();

    std::future_status status = future.wait_for(std::chrono::seconds(timeoutSec));
    if (status != std::future_status::ready) {
        IAM_LOGE("RunOnResidentSync timeout - task not completed in %{public}u second, status: %{public}d", timeoutSec,
            static_cast<int32_t>(status));
        return TIMEOUT;
    }
    return future.get();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
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

#include "user_launch_service_callback_service.h"

#include "callback_manager.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "user_launch_service_client_impl.h"

#define LOG_TAG "USER_LAUNCH_SERVICE_SDK"
#define LOG_FILE_ID LOG_FILE_USER_LAUNCH_SERVICE_CALLBACK_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {

LaunchServiceCallbackService::LaunchServiceCallbackService(
    const std::shared_ptr<LaunchServiceCallback> &impl) : operateCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, launch service callback return default result to caller");
            impl->OnResult(GENERAL_ERROR);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

LaunchServiceCallbackService::~LaunchServiceCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t LaunchServiceCallbackService::OnLaunchServiceResult(int32_t resultCode)
{
    IAM_LOGD("start, result:%{public}d", resultCode);
    if (operateCallback_ == nullptr) {
        IAM_LOGE("operate callback is nullptr");
        return GENERAL_ERROR;
    }
    operateCallback_->OnResult(resultCode);
    return SUCCESS;
}

int32_t LaunchServiceCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t LaunchServiceCallbackService::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}

LaunchServiceListCallbackService::LaunchServiceListCallbackService(
    const std::shared_ptr<LaunchServiceListCallback> &impl) : listCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, launch service list callback return default result to caller");
            impl->OnResult(GENERAL_ERROR, std::vector<LaunchServiceFlatInfo>{});
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

LaunchServiceListCallbackService::~LaunchServiceListCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t LaunchServiceListCallbackService::OnLaunchServiceListResult(int32_t resultCode,
    const std::vector<IpcLaunchServiceFlatInfo> &serviceList)
{
    IAM_LOGD("start, result:%{public}d, list size:%{public}zu", resultCode, serviceList.size());
    if (listCallback_ == nullptr) {
        IAM_LOGE("list callback is nullptr");
        return GENERAL_ERROR;
    }
    std::vector<LaunchServiceFlatInfo> infoList;
    for (const auto &item : serviceList) {
        LaunchServiceFlatInfo info = {};
        info.uid = item.uid;
        info.serviceKey = LaunchServiceKey{item.serviceKey.serviceName, item.serviceKey.moduleName};
        info.bundleInfo = BundleExtInfo{item.bundleInfo.ownerBundleName, item.bundleInfo.appIndex,
            item.bundleInfo.appIdentifier};
        info.serviceInfo = ServiceExtInfo{static_cast<LaunchServiceType>(item.serviceInfo.serviceType),
            item.serviceInfo.additionalInfo};
        info.activeState = static_cast<LaunchServiceState>(item.activeState);
        info.isForbidden = item.isForbidden;
        info.launchServiceSize = item.launchServiceSize;
        infoList.push_back(std::move(info));
    }
    listCallback_->OnResult(resultCode, infoList);
    return SUCCESS;
}

int32_t LaunchServiceListCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t LaunchServiceListCallbackService::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

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

#include "device_manager_listener.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_time.h"
#include "iam_executor_framework_types.h"

#include "hisysevent_adapter.h"
#include "iservmgr_hdi.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_DEVICE_MANAGER_LISTENER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
DeviceManagerListener::DeviceManagerListener(const std::string &serviceName,
    OnHdiConnectCallback onConnect, OnHdiDisconnectCallback onDisconnect)
    : serviceName_(serviceName), onHdiConnectFunc_(std::move(onConnect)), onHdiDisconnectFunc_(std::move(onDisconnect))
{}

DeviceManagerListener::~DeviceManagerListener()
{
    IAM_LOGI("device manager destory");
    UpdateServiceStatusListener(nullptr);
    UpdateSystemAbilityListener(nullptr);
}

void DeviceManagerListener::Subscribe()
{
    IAM_LOGI("device manager subscribe");
    auto weakSelf = std::weak_ptr<DeviceManagerListener>(shared_from_this());
    auto listener = SystemAbilityListener::Subscribe("DriverManager", DEVICE_SERVICE_MANAGER_SA_ID,
        [weakSelf]() {
            auto self = weakSelf.lock();
            if (self != nullptr) {
                self->OnStart();
            }
        },
        [weakSelf]() {
            auto self = weakSelf.lock();
            if (self != nullptr) {
                self->OnRemove();
            }
        });
    UpdateSystemAbilityListener(listener);
}

void DeviceManagerListener::OnStart()
{
    IAM_LOGI("device manager on start");
    auto servMgr = HDI::ServiceManager::V1_0::IServiceManager::Get();
    IF_FALSE_LOGE_AND_RETURN(servMgr != nullptr);

    std::string serviceName = serviceName_;
    OnHdiConnectCallback onConnect = onHdiConnectFunc_;
    OnHdiDisconnectCallback onDisconnect = onHdiDisconnectFunc_;
    auto listener = sptr<HdiServiceStatusListener>(new (std::nothrow) HdiServiceStatusListener(
        [serviceName, onConnect, onDisconnect](const ServiceStatus &status) {
            if (status.serviceName != serviceName) {
                return;
            }

            switch (status.status) {
                case HDI::ServiceManager::V1_0::SERVIE_STATUS_START:
                    IAM_LOGI("service %{public}s status change to start", status.serviceName.c_str());
                    if (onConnect != nullptr) {
                        onConnect();
                    }
                    break;
                case HDI::ServiceManager::V1_0::SERVIE_STATUS_STOP:
                    UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), status.serviceName);
                    IAM_LOGI("service %{public}s status change to stop", status.serviceName.c_str());
                    if (onDisconnect != nullptr) {
                        onDisconnect();
                    }
                    break;
                default:
                    IAM_LOGI("service %{public}s status ignored", status.serviceName.c_str());
            }
        }
    ));
    IF_FALSE_LOGE_AND_RETURN(listener != nullptr);
#ifndef IAM_TEST_ENABLE
    int32_t ret = servMgr->RegisterServiceStatusListener(listener, DEVICE_CLASS_USERAUTH);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("failed to register service status listener");
        return;
    }
#endif
    UpdateServiceStatusListener(listener);
}

void DeviceManagerListener::OnRemove()
{
    IAM_LOGI("device manager on remove");
    if (onHdiDisconnectFunc_ != nullptr) {
        onHdiDisconnectFunc_();
    }

    UpdateServiceStatusListener(nullptr);
}

void DeviceManagerListener::UpdateServiceStatusListener(sptr<HdiServiceStatusListener> listener)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (serviceStatusListener_) {
        auto servMgr = HDI::ServiceManager::V1_0::IServiceManager::Get();
        if (servMgr) {
            int32_t ret = servMgr->UnregisterServiceStatusListener(serviceStatusListener_);
            IAM_LOGI("UnregisterServiceStatusListener ret:%{public}d", ret);
        }
    }
    serviceStatusListener_ = listener;
}

void DeviceManagerListener::UpdateSystemAbilityListener(sptr<SystemAbilityListener> listener)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (systemAbilityListener_) {
        int32_t ret = SystemAbilityListener::UnSubscribe(DEVICE_SERVICE_MANAGER_SA_ID, systemAbilityListener_);
        IAM_LOGI("unsubscribe result %{public}d", ret);
    }
    systemAbilityListener_ = listener;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

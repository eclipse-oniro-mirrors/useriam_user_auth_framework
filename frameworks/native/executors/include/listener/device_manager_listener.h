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

#ifndef DEVICE_MANAGER_LISTENER_H
#define DEVICE_MANAGER_LISTENER_H

#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "iservstat_listener_hdi.h"
#include "nocopyable.h"
#include "system_ability_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using ServStatListenerStub = HDI::ServiceManager::V1_0::ServStatListenerStub;
using ServiceStatus = HDI::ServiceManager::V1_0::ServiceStatus;

class DeviceManagerListener : public std::enable_shared_from_this<DeviceManagerListener>, public NoCopyable {
public:
    using OnHdiConnectCallback = std::function<void()>;
    using OnHdiDisconnectCallback = std::function<void()>;

    DeviceManagerListener(const std::string &serviceName, OnHdiConnectCallback onConnect,
        OnHdiDisconnectCallback onDisconnect);
    ~DeviceManagerListener() override;

    void Subscribe();

private:
    class HdiServiceStatusListener;
    void OnStart();
    void OnRemove();
    void UpdateServiceStatusListener(sptr<HdiServiceStatusListener> listener);
    void UpdateSystemAbilityListener(sptr<SystemAbilityListener> listener);

    std::recursive_mutex mutex_;
    std::string serviceName_ = {};
    OnHdiConnectCallback onHdiConnectFunc_;
    OnHdiDisconnectCallback onHdiDisconnectFunc_;
    sptr<HdiServiceStatusListener> serviceStatusListener_ = {};
    sptr<SystemAbilityListener> systemAbilityListener_ = {};
};

class DeviceManagerListener::HdiServiceStatusListener : public ServStatListenerStub {
public:
    using StatusCallback = std::function<void(const ServiceStatus &)>;
    explicit HdiServiceStatusListener(StatusCallback callback) : callback_(std::move(callback))
    {
    }
    ~HdiServiceStatusListener() override = default;
    void OnReceive(const ServiceStatus &status) override
    {
        if (!callback_) {
            return;
        }
        callback_(status);
    }

private:
    StatusCallback callback_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // DEVICE_MANAGER_LISTENER_H
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

#ifndef EXECUTOR_DRIVER_H
#define EXECUTOR_DRIVER_H

#include <string>
#include <vector>

#include "nocopyable.h"

#include "device_manager_listener.h"
#include "executor.h"
#include "framework_ready_listener.h"
#include "iam_executor_idriver_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Driver : public std::enable_shared_from_this<Driver>, public NoCopyable {
public:
    Driver(const std::string &serviceName, HdiConfig hdiConfig);
    ~Driver() override = default;

    void Init();
    void OnHdiConnect();
    void OnHdiDisconnect();
    void OnFrameworkReady();
    void OnFrameworkDown();

private:
    void RegisterExecutors();
    void SubscribeFrameworkReadyListener();
    void SubscribeDeviceManagerListener();

    std::recursive_mutex mutex_;
    bool hdiConnected_ = false;
    bool isFwkReady_ = false;
    std::vector<std::shared_ptr<Executor>> executorList_;

    std::string serviceName_;
    HdiConfig hdiConfig_;
    std::shared_ptr<DeviceManagerListener> deviceManagerListener_;
    std::shared_ptr<FrameworkReadyListener> frameworkReadyListener_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // EXECUTOR_DRIVER_H
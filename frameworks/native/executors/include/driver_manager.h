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

#ifndef DRIVER_MANAGER_H
#define DRIVER_MANAGER_H

#include <cstdint>
#include <map>

#include "singleton.h"

#include "driver.h"
#include "iam_executor_iauth_driver_hdi.h"
#include "iam_executor_idriver_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class DriverManager : public Singleton<DriverManager> {
public:
    DriverManager();
    ~DriverManager() override = default;
    int32_t Start(const std::map<std::string, HdiConfig> &hdiName2Config, bool hasHdi);

private:
    bool HdiConfigIsValid(const std::map<std::string, HdiConfig> &hdiName2Config);

    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Driver>> serviceName2Driver_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // DRIVER_MANAGER_H
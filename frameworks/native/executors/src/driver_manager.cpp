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

#include "driver_manager.h"

#include <set>

#include "iservmgr_hdi.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_param_manager.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_DRIVER_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace HDI::ServiceManager::V1_0;
DriverManager::DriverManager() {}

int32_t DriverManager::Start(const std::map<std::string, HdiConfig> &hdiName2Config, bool hasHdi)
{
    IAM_LOGI("DriverManager start");
    if (!HdiConfigIsValid(hdiName2Config)) {
        IAM_LOGE("service config is not valid");
        return USERAUTH_ERROR;
    }
    auto servMgr = IServiceManager::Get();
    IF_FALSE_LOGE_AND_RETURN_VAL(servMgr != nullptr, USERAUTH_ERROR);
    for (auto const &[hdiName, config] : hdiName2Config) {
        auto driver = Common::MakeShared<Driver>(hdiName, config);
        if (driver == nullptr) {
            IAM_LOGE("MakeShared for driver %{public}s failed", hdiName.c_str());
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (serviceName2Driver_.find(hdiName) != serviceName2Driver_.end()) {
                IAM_LOGI("%{public}s already added, skip", hdiName.c_str());
                continue;
            }
            serviceName2Driver_[hdiName] = driver;
        }
        driver->Init();
        if (hasHdi) {
            auto service = servMgr->GetService(hdiName.c_str());
            if (service != nullptr) {
                driver->OnHdiConnect();
            }
        } else {
            driver->OnHdiConnect();
        }
        IAM_LOGI("add driver %{public}s", hdiName.c_str());
    }
    return USERAUTH_SUCCESS;
}

bool DriverManager::HdiConfigIsValid(const std::map<std::string, HdiConfig> &hdiName2Config)
{
    std::set<uint16_t> idSet;
    for (auto const &[hdiName, config] : hdiName2Config) {
        uint16_t id = config.id;
        if (idSet.find(id) != idSet.end()) {
            IAM_LOGE("duplicate hdi id %{public}hu", id);
            return false;
        }
        if (config.driver == nullptr) {
            IAM_LOGE("driver is nullptr");
            return false;
        }
        idSet.insert(id);
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

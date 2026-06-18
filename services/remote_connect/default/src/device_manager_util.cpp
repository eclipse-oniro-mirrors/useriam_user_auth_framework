/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "device_manager_util.h"

#include "device_manager.h"
#include "parameter.h"

#include "iam_check.h"

#define LOG_FILE_ID LOG_FILE_DEVICE_MANAGER_UTIL
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using DeviceManager = OHOS::DistributedHardware::DeviceManager;
namespace {
static const std::string USER_AUTH_PACKAGE_NAME = "ohos.useriam";
}

DeviceManagerUtil &DeviceManagerUtil::GetInstance()
{
    static DeviceManagerUtil instance;
    return instance;
}

bool DeviceManagerUtil::GetUdidByNetworkId(const std::string &networkId, std::string &udid)
{
    int32_t ret = DeviceManager::GetInstance().GetUdidByNetworkId(USER_AUTH_PACKAGE_NAME, networkId, udid);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == 0, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(!udid.empty(), false);

    return true;
}

bool DeviceManagerUtil::GetLocalDeviceNetWorkId(std::string &networkId)
{
    int32_t ret = DeviceManager::GetInstance().GetLocalDeviceNetWorkId(USER_AUTH_PACKAGE_NAME, networkId);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == 0, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(!networkId.empty(), false);

    return true;
}

bool DeviceManagerUtil::GetLocalDeviceUdid(std::string &udid)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (localUdid_.has_value()) {
        udid = localUdid_.value();
        return true;
    }

    constexpr uint32_t MAX_UDID_STR_LEN = 65;
    char udidStr[MAX_UDID_STR_LEN] = { 0 };
    if (GetDevUdid(udidStr, MAX_UDID_STR_LEN) != 0) {
        IAM_LOGE("GetDevUdid failed");
        return false;
    }
    udid = udidStr;
    localUdid_ = udid;

    return true;
}

bool DeviceManagerUtil::GetNetworkIdByUdid(const std::string &udid, std::string &networkId)
{
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    int32_t ret = DeviceManager::GetInstance().GetTrustedDeviceList(USER_AUTH_PACKAGE_NAME, "", deviceList);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == 0, false);

    networkId = "";
    for (auto &device : deviceList) {
        std::string deviceUdid(device.deviceId);
        if (deviceUdid == udid) {
            networkId = std::string(device.networkId);
            break;
        }
    }
    if (networkId.empty()) {
        IAM_LOGE("networkId not found");
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
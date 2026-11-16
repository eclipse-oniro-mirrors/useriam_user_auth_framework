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

#include "device_manager_util.h"

#include "parameter.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
DeviceManagerUtil &DeviceManagerUtil::GetInstance()
{
    static DeviceManagerUtil instance;
    return instance;
}

bool DeviceManagerUtil::GetUdidByNetworkId(const std::string &networkId, std::string &udid)
{
    return false;
}

bool DeviceManagerUtil::GetLocalDeviceNetWorkId(std::string &networkId)
{
    networkId.clear();
    return false;
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
    auto udidRes = GetDevUdid(udidStr, MAX_UDID_STR_LEN);
    if (udidRes == 0 && strnlen(udidStr, MAX_UDID_STR_LEN) <= MAX_UDID_STR_LEN - 1) {
        udid = udidStr;
        localUdid_ = udid;
        return true;
    }
    return false;
}

bool DeviceManagerUtil::GetNetworkIdByUdid(const std::string &udid, std::string &networkId)
{
    return false;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DEVICE_MANAGER_UTIL_H
#define DEVICE_MANAGER_UTIL_H

#include <cstring>
#include <mutex>
#include <optional>
#include <string>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr uint32_t DEFAULT_MESSAGE_VERSION = 0;

class DeviceManagerUtil {
public:
    static DeviceManagerUtil &GetInstance();
    DeviceManagerUtil() = default;
    ~DeviceManagerUtil() = default;

    bool GetUdidByNetworkId(const std::string &networkId, std::string &udid);
    bool GetLocalDeviceNetWorkId(std::string &networkId);
    bool GetLocalDeviceUdid(std::string &udid);
    bool GetNetworkIdByUdid(const std::string &udid, std::string &networkId);

private:
    std::recursive_mutex mutex_;
    std::optional<std::string> localUdid_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // DEVICE_MANAGER_UTIL_H
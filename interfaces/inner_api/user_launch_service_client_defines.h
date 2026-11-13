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

/**
 * @file user_launch_service_client_defines.h
 *
 * @brief Type definitions used by user launch service client.
 * @since 7.1
 * @version 7.1
 */

#ifndef USER_LAUNCH_SERVICE_DEFINES_H
#define USER_LAUNCH_SERVICE_DEFINES_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
/**
 * @brief Describes the type of a launch service.
 */
enum class LaunchServiceType {
    /** Invalid service type. */
    INVALID = 0,
    /** Normal agent service. */
    NORMAL_AGENT = 1,
    /** Privileged daemon service. */
    PRIVILEGED_DAEMON = 2,
};

/**
 * @brief Describes the active state of a launch service.
 */
enum class LaunchServiceState {
    /** Deactivated. */
    DEACTIVATE = 1,
    /** Activated. */
    ACTIVATE = 2,
};

/**
 * @brief Describes the key to identify a launch service.
 */
struct LaunchServiceKey {
    /** Launch service name. Maximum length: 128 bytes. */
    std::string serviceName {};
    /** Module name. Maximum length: 128 bytes. */
    std::string moduleName {};
};

/**
 * @brief Describes the extension info of a service.
 */
struct ServiceExtInfo {
    /** Service type. */
    LaunchServiceType serviceType {};
    /** Service info assigned by AMS. Maximum length: 1K. */
    std::string additionalInfo {};
};

/**
 * @brief Describes the extension info of the bundle that owns the launch service.
 */
struct BundleExtInfo {
    /** Bundle name of the application that owns the service. Maximum length: 128 bytes. */
    std::string ownerBundleName {};
    /** Application index. */
    int32_t appIndex {};
    /** Application identifier. Maximum length: 128 bytes. */
    std::string appIdentifier {};
};

/**
 * @brief Describes the registration info of a launch service.
 */
struct LaunchServiceRegisterInfo {
    /** Caller uid. */
    int32_t uid {};
    /** Launch service key. */
    LaunchServiceKey serviceKey {};
    /** Bundle extension info. */
    BundleExtInfo bundleInfo {};
    /** Service extension info. */
    ServiceExtInfo serviceInfo {};
};

/**
 * @brief Describes the info of a registered launch service.
 */
struct LaunchServiceFlatInfo {
    /** bundle uid. */
    int32_t uid {};
    /** Launch service key. */
    LaunchServiceKey serviceKey {};
    /** Bundle extension info. */
    BundleExtInfo bundleInfo {};
    /** Service extension info. */
    ServiceExtInfo serviceInfo {};
    /** Active state of the service. */
    LaunchServiceState activeState {};
    /** Whether the service is forbidden. */
    bool isForbidden {};
    /** The number of services registered by application */
    uint32_t launchServiceSize {};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_LAUNCH_SERVICE_DEFINES_H

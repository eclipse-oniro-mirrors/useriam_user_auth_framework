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
 * @file user_launch_service_client_callback.h
 *
 * @brief Callback definitions returned by user launch service client.
 * @since 7.1
 * @version 7.1
 */

#ifndef USER_LAUNCH_SERVICE_CALLBACK_H
#define USER_LAUNCH_SERVICE_CALLBACK_H

#include <vector>

#include "user_launch_service_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
/**
 * @brief Callback for launch service operation result.
 *
 * Used by RegisterLaunchService, UnRegisterLaunchService, and SetLaunchServiceState
 * to return the operation result code.
 */
class LaunchServiceCallback {
public:
    /**
     * @brief Deconstructor.
     */
    virtual ~LaunchServiceCallback() = default;

    /**
     * @brief Called when the launch service operation is completed.
     *
     * @param result The result code (0:success; other:failed).
     */
    virtual void OnResult(int32_t result) = 0;
};

/**
 * @brief Callback for querying a list of launch service infos.
 *
 * Used by GetLaunchServiceList to return the result along with the queried list.
 */
class LaunchServiceListCallback {
public:
    /**
     * @brief Deconstructor.
     */
    virtual ~LaunchServiceListCallback() = default;

    /**
     * @brief Called when the launch service list query is completed.
     *
     * @param result The result code (0:success; other:failed).
     * @param serviceList The queried launch service list.
     */
    virtual void OnResult(int32_t result, const std::vector<LaunchServiceFlatInfo> &serviceList) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_LAUNCH_SERVICE_CALLBACK_H

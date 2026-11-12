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

/**
 * @file user_access_ctrl_client.h
 *
 * @brief The definition of user access ctrl client.
 * @since 5.1
 * @version 1.0
 */

#ifndef USER_ACCESS_CTRL_CLIENT_H
#define USER_ACCESS_CTRL_CLIENT_H

#include <memory>
#include <vector>

#include "user_access_ctrl_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAccessCtrlClient {
public:
    /**
     * @brief Get user access ctrl client's instance.
     *
     * @return UserAccessCtrlClient's instance.
     */
    static UserAccessCtrlClient &GetInstance();

    /**
     * @brief Deconstructor.
     */
    virtual ~UserAccessCtrlClient() = default;

    /**
     * @brief Verify token and return the plainText.
     *
     * @param tokenIn Token signed by userAuth.
     * @param allowableDuration Allowable duration of token.
     * @param callback Callback of verify auth token result.
     *
     * @return Return get result(0:success; other:failed).
     */
    virtual void VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        const std::shared_ptr<VerifyTokenCallback> &callback) = 0;

    /**
     * @brief Redeem a scheduled auth token to a real-time auth token.
     */
    virtual void RedeemScheduledAuthToken(const std::vector<uint8_t> &challenge,
        const std::vector<uint8_t> &scheduleToken,
        const std::shared_ptr<VerifyTokenCallback> &callback) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_ACCESS_CTRL_CLIENT_H
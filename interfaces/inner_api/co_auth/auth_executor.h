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

#ifndef AUTH_EXECUTOR_H
#define AUTH_EXECUTOR_H

#include <vector>
#include <cstdint>
#include <cstdlib>
#include <iremote_broker.h>
#include "co_auth_info_define.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthExecutor {
public:
    AuthExecutor();
    ~AuthExecutor();

    /* Actuator information acquisition */
    int32_t GetAuthType(AuthType &value);                     // Credential type
    int32_t GetAuthAbility(uint64_t &value);                  // Actuator capability
    int32_t GetExecutorSecLevel(ExecutorSecureLevel &value);  // Safety level
    int32_t GetExecutorType(ExecutorType &value);             // Actuator type
    int32_t GetPublicKey(std::vector<uint8_t> &value);        // Public key
    int32_t GetDeviceId(std::vector<uint8_t> &value);         // Device ID

    /* Actuator information setting */
    int32_t SetAuthType(const AuthType value);                     // Credential type
    int32_t SetAuthAbility(const uint64_t value);                  // Actuator capability
    int32_t SetExecutorSecLevel(const ExecutorSecureLevel value);  // Safety level
    int32_t SetExecutorType(const ExecutorType value);             // Actuator type
    int32_t SetPublicKey(const std::vector<uint8_t> &value);       // Public key
    int32_t SetDeviceId(const std::vector<uint8_t> &value);        // Device ID

private:
    AuthType authTypeValue_;
    uint64_t authAbilityValue_;
    ExecutorSecureLevel executorSecLevelValue_;
    ExecutorType executorTypeValue_;
    std::vector<uint8_t> publicKeyValue_;
    std::vector<uint8_t> deviceIdValue_;
};
}  // namespace AuthResPool
}  // namespace userIAM
}  // namespace ohos
namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
using AuthExecutor = OHOS::UserIam::UserAuth::AuthExecutor;
}
}
}
#endif  // AUTH_EXECUTOR_H
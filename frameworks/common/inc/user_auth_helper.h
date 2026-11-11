/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef USER_AUTH_HELPER
#define USER_AUTH_HELPER

#include <string>
#include <vector>

#include "attributes.h"
#include "auth_common.h"
#include "user_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthHelper {
public:
    static bool CheckUserAuthType(int32_t authType);
    static bool CheckAuthTrustLevel(uint32_t authTrustLevel);
    static bool CheckAuthTokenParam(const std::vector<uint8_t> &authToken);
    static bool CheckChallengeParam(const std::vector<uint8_t> &challenge);
    static int32_t CheckTokenSchedule(const std::optional<TokenSchedule> &schedule);
    static bool SetTokenScheduleAttr(const std::optional<TokenSchedule> &schedule, Attributes &extraInfo);
    static bool GetTokenScheduleAttr(const Attributes &extraInfo, TokenSchedule &schedule);
    static int32_t GetResultCodeV10(int32_t result);
    static UserAuthResultCode GetResultCodeV16(int32_t result);
    static UserAuthResultCode GetResultCodeV26(int32_t result);
    static int32_t GetResultCodeV20(int32_t result);
    static int32_t GetResultCodeV21(int32_t result);
    static bool CheckReuseUnlockResult(ReuseUnlockResult reuseUnlockResult);
    static size_t GetUtf8CharCount(const std::string &str);
private:
    UserAuthHelper() = default;
    ~UserAuthHelper() = default;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_AUTH_HELPER

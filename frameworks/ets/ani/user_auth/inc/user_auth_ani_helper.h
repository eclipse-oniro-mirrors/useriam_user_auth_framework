/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_ANI_HELPER
#define USER_AUTH_ANI_HELPER

#include <string>
#include <vector>

#include "nocopyable.h"
#include "ohos.userIAM.userAuth.userAuth.proj.hpp"

#include "auth_common.h"
#include "user_auth_client_defines.h"

namespace userAuth = ohos::userIAM::userAuth::userAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthAniHelper {
public:
    static UserAuthResultCode ThrowBusinessError(UserAuthResultCode error);
    static UserAuthResultCode ThrowBusinessError(UserAuthResultCode error, const std::string &errorMsg);
    static bool IsSystemApiCaller();
    static bool VerifyNoticeParam(const std::string &eventData);
    static bool ConvertUserAuthType(int32_t userAuthType, userAuth::UserAuthType &userAuthTypeOut);
    static bool ConvertUserAuthTipCode(int32_t userAuthTipCode, userAuth::UserAuthTipCode &userAuthTipCodeOut);

private:
    UserAuthAniHelper() = default;
    ~UserAuthAniHelper() = default;
};
}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS

#endif  // USER_AUTH_ANI_HELPER

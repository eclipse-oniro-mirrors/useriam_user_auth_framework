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

#ifndef USER_AUTH_CALLBACK_V10_H
#define USER_AUTH_CALLBACK_V10_H

#include <mutex>

#include "nocopyable.h"
#include "ohos.userIAM.userAuth.userAuth.proj.hpp"

#include "iam_ptr.h"
#include "auth_common.h"
#include "iam_common_defines.h"
#include "user_auth_ani_helper.h"
#include "user_auth_client.h"
#include "user_auth_common_defines.h"

namespace userAuth = ohos::userIAM::userAuth::userAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using AuthTipCallback = taihe::callback<void(userAuth::AuthTipInfo const &)>;
using AuthTipCallbackPtr = std::shared_ptr<taihe::optional<AuthTipCallback>>;
using AcquireInfoCallback = AuthTipCallback;
using AcquireInfoCallbackPtr = AuthTipCallbackPtr;

class UserAuthCallbackV10 : public AuthenticationCallback,
                            public std::enable_shared_from_this<UserAuthCallbackV10>,
                            public NoCopyable {
public:
    UserAuthCallbackV10() = default;
    ~UserAuthCallbackV10() override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void SetResultCallback(const userAuth::IAuthCallback &resultCallback);
    void ClearResultCallback();
    bool HasResultCallback();
    void SetTipCallback(taihe::optional<AuthTipCallback> tipCallback);
    void ClearTipCallback();
    bool HasTipCallback();
    void SetAcquireInfoCallback(taihe::optional<AcquireInfoCallback> acquireInfoCallback);
    void ClearAcquireInfoCallback();
    bool HasAcquireInfoCallback();

private:
    bool DoResultCallback(int32_t result, const Attributes &extraInfo);
    bool DoTipInfoCallBack(int32_t tipType, uint32_t tipCode);
    bool DoAcquireInfoCallBack(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo);
    AuthTipCallbackPtr GetTipCallback();
    AcquireInfoCallbackPtr GetAcquireInfoCallback();
    std::mutex mutex_;
    std::shared_ptr<userAuth::IAuthCallback> resultCallback_ = nullptr;
    AuthTipCallbackPtr tipCallback_ = nullptr;
    AcquireInfoCallbackPtr acquireInfoCallback_ = nullptr;
};
}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS

#endif  // USER_AUTH_CALLBACK_V10_H

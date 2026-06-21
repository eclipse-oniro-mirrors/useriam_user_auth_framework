/*
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

#ifndef USER_AUTH_INSTANCE_V10_H
#define USER_AUTH_INSTANCE_V10_H

#include <mutex>

#include "ability.h"
#include "nocopyable.h"

#include "iam_ptr.h"
#include "auth_common.h"
#include "user_auth_client_defines.h"
#include "user_auth_callback_v10.h"
#include "user_auth_napi_client_impl.h"
#include "user_auth_modal_callback.h"

#include "ohos.userIAM.userAuth.userAuth.proj.hpp"

namespace userAuth = ohos::userIAM::userAuth::userAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthInstanceV10 : public NoCopyable {
public:
    explicit UserAuthInstanceV10();
    ~UserAuthInstanceV10() = default;

    UserAuthResultCode Init(userAuth::AuthParam const &authParam, userAuth::WidgetParam const &widgetParam);
    UserAuthResultCode OnResult(userAuth::IAuthCallback const &callback);
    UserAuthResultCode OffResult(taihe::optional_view<userAuth::IAuthCallback> callback);
    UserAuthResultCode Start();
    UserAuthResultCode Cancel();
    UserAuthResultCode onAuthTip(taihe::callback_view<void(userAuth::AuthTipInfo const&)> callback);
    UserAuthResultCode offAuthTip(taihe::optional_view<taihe::callback<void(userAuth::AuthTipInfo const&)>> callback);

private:
    uint64_t contextId_ = 0;
    bool isAuthStarted_ = false;

    AuthParamInner authParam_ = {};
    WidgetParamNapi widgetParam_ = {};

    std::mutex mutex_;
    std::shared_ptr<UserAuthCallbackV10> callback_ = nullptr;
    std::shared_ptr<UserAuthModalCallback> modalCallback_ = nullptr;
    std::shared_ptr<AbilityRuntime::Context> context_ = nullptr;
};
}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS

#endif  // USER_AUTH_INSTANCE_V10_H

/*
* Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_PARAM_UTILS_H
#define USER_AUTH_PARAM_UTILS_H

#include <mutex>

#include "nocopyable.h"

#include "ability.h"
#include "ohos.userIAM.userAuth.userAuth.proj.hpp"

#include "auth_common.h"
#include "user_auth_napi_client_impl.h"
#include "user_auth_api_event_reporter.h"

namespace userAuth = ohos::userIAM::userAuth::userAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {

class UserAuthParamUtils : public NoCopyable {
public:
    static UserAuthResultCode InitAuthParam(userAuth::AuthParam const &authParam, AuthParamInner &authParamInner);
    static UserAuthResultCode InitWidgetParam(userAuth::WidgetParam const &widgetParam,
        WidgetParamNapi &widgetParamNapi, std::shared_ptr<AbilityRuntime::Context> &abilityContext);

private:
    static UserAuthResultCode InitAuthType(userAuth::AuthParam const &authParam, AuthParamInner &authParamInner);
    static UserAuthResultCode InitAuthTrustLevel(userAuth::AuthParam const &authParam, AuthParamInner &authParamInner);
    static UserAuthResultCode InitReuseUnlockResult(userAuth::AuthParam const &authParam,
        AuthParamInner &authParamInner);
    static UserAuthResultCode InitUserId(userAuth::AuthParam const &authParam, AuthParamInner &authParamInner);
    static UserAuthResultCode InitSkipLockedBiometricAuth(userAuth::AuthParam const &authParam,
        AuthParamInner &authParamInner);
    static UserAuthResultCode InitCredentialIdList(userAuth::AuthParam const &authParam,
        AuthParamInner &authParamInner);
    static UserAuthResultCode InitTitle(userAuth::WidgetParam const &widgetParam, WidgetParamNapi &widgetParamNapi);
    static UserAuthResultCode InitNavigationButtonText(userAuth::WidgetParam const &widgetParam,
        WidgetParamNapi &widgetParamNapi);
    static UserAuthResultCode InitWindowMode(userAuth::WidgetParam const &widgetParam,
        WidgetParamNapi &widgetParamNapi);
    static UserAuthResultCode InitContext(userAuth::WidgetParam const &widgetParam,
        WidgetParamNapi &widgetParamNapi, std::shared_ptr<AbilityRuntime::Context> &abilityContext);
    static bool CheckUIContext(const std::shared_ptr<OHOS::AbilityRuntime::Context> context);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_PARAM_UTILS_H
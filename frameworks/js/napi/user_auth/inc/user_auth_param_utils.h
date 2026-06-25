/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "window.h"
#include "nocopyable.h"

#include "ability.h"

#include "auth_common.h"
#include "user_auth_napi_client_impl.h"
#include "user_auth_api_event_reporter.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthParamUtils : public NoCopyable {
public:
    static UserAuthResultCode InitAuthParam(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode InitWidgetParam(napi_env env, napi_value value,
        WidgetParamNapi &widgetParam, std::shared_ptr<AbilityRuntime::Context> &abilityContext,
        sptr<OHOS::Rosen::Window> &window);

private:
    static UserAuthResultCode InitChallenge(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode InitAuthType(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode InitAuthTrustLevel(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode InitReuseUnlockResult(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode InitUserId(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode ProcessAuthTrustLevelAndUserId(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode ProcessReuseUnlockResult(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode ProcessWindowMode(napi_env env, napi_value value,
        WidgetParamNapi &widgetParam);
    static UserAuthResultCode ProcessContext(napi_env env, napi_value value,
        WidgetParamNapi &widgetParam,
        std::shared_ptr<AbilityRuntime::Context> &abilityContext);
    static UserAuthResultCode ProcessWindow(napi_env env, napi_value value,
        WidgetParamNapi &widgetParam, sptr<OHOS::Rosen::Window> &window);
    static bool CheckUIContext(const std::shared_ptr<OHOS::AbilityRuntime::Context> context);
    static UserAuthResultCode ProcessSkipLockedBiometricAuth(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode ProcessCredentialIdList(napi_env env, napi_value value, AuthParamInner &authParam);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_PARAM_UTILS_H

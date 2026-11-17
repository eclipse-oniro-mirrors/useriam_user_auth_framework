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
#include "set_widget_param_callback.h"
#include "user_auth_napi_client_impl.h"
#include "user_auth_api_event_reporter.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum class AuthApiContract {
    USER_AUTH_INSTANCE,
    SYSTEM_USER_AUTH,
    QUERY_REUSABLE_RESULT,
};

class UserAuthParamUtils : public NoCopyable {
public:
    explicit UserAuthParamUtils(AuthApiContract contract);

    UserAuthResultCode InitAuthParam(napi_env env, napi_value value, AuthParamInner &authParam);
    static UserAuthResultCode InitWidgetParam(napi_env env, napi_value value,
        SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt,
        std::shared_ptr<AbilityRuntime::Context> &abilityContext, sptr<OHOS::Rosen::Window> &window);

private:
    UserAuthResultCode ParamVerifyFailedCode() const;
    UserAuthResultCode InitChallenge(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode InitAuthType(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode InitAuthTrustLevel(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode InitReuseUnlockResult(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode InitUserId(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode ProcessUserId(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode ProcessReuseUnlockResult(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode ProcessSkipLockedBiometricAuth(napi_env env, napi_value value,
        AuthParamInner &authParam);
    UserAuthResultCode ProcessCredentialIdList(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode ProcessAuthIntent(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode ProcessRemoteAuthOptions(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode ProcessAdditionalInfo(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode ProcessScheduledAuthTokenOptions(napi_env env, napi_value value,
        AuthParamInner &authParam);
    UserAuthResultCode InitMandatoryAuthParam(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode InitOptionalAuthParam(napi_env env, napi_value value, AuthParamInner &authParam);
    UserAuthResultCode ProcessRemoteNetworkId(napi_env env, napi_value remoteValue,
        const std::string &propertyName, std::optional<std::string> &networkId);
    UserAuthResultCode ProcessCollectorTokenId(napi_env env, napi_value remoteValue,
        RemoteAuthParam &remoteAuthParam);
    UserAuthResultCode ReadMandatoryInt64Field(napi_env env, napi_value value,
        const std::string &propertyName, int64_t &out);
    UserAuthResultCode ReadOptionalInt64Field(napi_env env, napi_value value,
        const std::string &propertyName, bool &hasValue, int64_t &out);
    UserAuthResultCode ReadWindowConfig(napi_env env, napi_value scheduleValue,
        std::optional<RedemptionWindow> &windowConfig);
    static UserAuthResultCode ProcessWindowMode(napi_env env, napi_value value,
        SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt);
    static UserAuthResultCode ProcessContext(napi_env env, napi_value value,
        SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt,
        std::shared_ptr<AbilityRuntime::Context> &abilityContext);
    static UserAuthResultCode ProcessWindow(napi_env env, napi_value value,
        SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt, sptr<OHOS::Rosen::Window> &window);
    static bool CheckUIContext(const std::shared_ptr<OHOS::AbilityRuntime::Context> context);

    AuthApiContract contract_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_PARAM_UTILS_H

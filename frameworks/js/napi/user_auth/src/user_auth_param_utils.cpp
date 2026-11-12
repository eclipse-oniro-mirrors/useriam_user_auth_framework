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

#include "user_auth_param_utils.h"

#include <algorithm>
#include <cinttypes>
#include <string>

#include "js_window.h"
#include "window.h"
#include "napi_base_context.h"
#include "ui_content.h"
#include "ui_extension_context.h"
#include "ui_holder_extension_context.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "user_auth_common_defines.h"
#include "user_auth_helper.h"
#include "user_auth_napi_helper.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_PARAM_UTILS

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const std::string AUTH_PARAM_CHALLENGE = "challenge";
    const std::string AUTH_PARAM_AUTHTYPE = "authType";
    const std::string AUTH_PARAM_AUTHTRUSTLEVEL = "authTrustLevel";
    const std::string AUTH_PARAM_REUSEUNLOCKRESULT = "reuseUnlockResult";
    const std::string AUTH_PARAM_USER_ID = "userId";
    const std::string AUTH_PARAM_SKIP_LOCKED_BIOMETRIC_AUTH = "skipLockedBiometricAuth";
    const std::string AUTH_PARAM_CREDENTIAL_ID_LIST = "credentialIdList";
    const std::string AUTH_PARAM_AUTH_INTENT = "authIntent";
    const std::string AUTH_PARAM_REMOTE_AUTH_OPTIONS = "remoteAuthOptions";
    const std::string REMOTE_PARAM_VERIFIER_NETWORK_ID = "verifierNetworkId";
    const std::string REMOTE_PARAM_COLLECTOR_NETWORK_ID = "collectorNetworkId";
    const std::string REMOTE_PARAM_COLLECTOR_TOKEN_ID = "collectorTokenId";
    const std::string AUTH_PARAM_ADDITIONAL_INFO = "additionalInfo";
    const std::string AUTH_PARAM_SCHEDULED_AUTH_TOKEN_OPTIONS = "scheduledAuthTokenOptions";
    const std::string SCHEDULE_PARAM_VALID_START_TIME = "validStartTime";
    const std::string SCHEDULE_PARAM_VALID_END_TIME = "validEndTime";
    const std::string SCHEDULE_PARAM_WINDOW_CONFIG = "windowConfig";
    const std::string SCHEDULE_PARAM_REPEAT_INTERVAL = "repeatInterval";
    const std::string SCHEDULE_PARAM_WINDOW_DURATION = "windowDuration";
    const std::string WIDGET_PARAM_TITLE = "title";
    const std::string WIDGET_PARAM_NAVIBTNTEXT = "navigationButtonText";
    const std::string WIDGET_PARAM_WINDOWMODE = "windowMode";
    const std::string WIDGET_PARAM_CONTEXT = "uiContext";
    const std::string WIDGET_PARAM_WINDOW = "appWindow";
    const std::string NOTICETYPE = "noticeType";
    const std::string REUSEMODE = "reuseMode";
    const std::string REUSEDURATION = "reuseDuration";
}

namespace WidgetType {
    constexpr int32_t BUTTON_MAX = 60;
}

namespace RemoteLimit {
    constexpr size_t MAX_NETWORK_ID_LEN = 64;
}

bool IsNullOrUndefined(napi_env env, napi_value value)
{
    return UserAuthNapiHelper::CheckNapiType(env, value, napi_null) == napi_ok ||
        UserAuthNapiHelper::CheckNapiType(env, value, napi_undefined) == napi_ok;
}

UserAuthResultCode UserAuthParamUtils::InitChallenge(napi_env env, napi_value value, AuthParamInner &authParam)
{
    authParam.challenge.clear();
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("challenge is null");
        std::string msgStr = "Parameter error. The type of \"challenge\" must be Uint8Array.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    ret = UserAuthNapiHelper::GetUint8ArrayValue(env, value, MAX_CHALLENG_LEN, authParam.challenge);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint8ArrayValue fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The length of \"challenge\" connot exceed 32.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    IAM_LOGI("challenge size:%{public}zu", authParam.challenge.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitAuthType(napi_env env, napi_value value, AuthParamInner &authParam)
{
    bool isArray = false;
    napi_is_array(env, value, &isArray);
    if (!isArray) {
        IAM_LOGI("authType is not array");
        std::string msgStr = "Parameter error. The type of \"authType\" must be array.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    uint32_t length = 0;
    napi_get_array_length(env, value, &length);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value jsValue = nullptr;
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            IAM_LOGE("scope is invalid");
            continue;
        }
        napi_get_element(env, value, i, &jsValue);
        if (jsValue == nullptr) {
            napi_close_handle_scope(env, scope);
            continue;
        }
        int32_t value = 0;
        napi_status ret = UserAuthNapiHelper::GetInt32Value(env, jsValue, value);
        napi_close_handle_scope(env, scope);
        if (ret != napi_ok) {
            IAM_LOGE("napi authType GetUint32Value fail:%{public}d", ret);
            std::string msgStr = "Parameter error. The type of \"authType\" must be number.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
        IAM_LOGI("napi get authType:%{public}d", value);
        if (!UserAuthHelper::CheckUserAuthType(value)) {
            IAM_LOGE("authType is illegal, %{public}d", value);
            return UserAuthResultCode::TYPE_NOT_SUPPORT;
        }
        auto iter = std::find(authParam.authTypes.begin(), authParam.authTypes.end(), static_cast<AuthType>(value));
        if (iter != authParam.authTypes.end()) {
            IAM_LOGE("napi authType:%{public}d exist", value);
            std::string msgStr = "Parameter error. The type of \"authType\" must be AuthType.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
        authParam.authTypes.push_back(static_cast<AuthType>(value));
    }

    IAM_LOGI("authType size:%{public}zu", authParam.authTypes.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitAuthTrustLevel(napi_env env, napi_value value, AuthParamInner &authParam)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("authTrustLevel is null");
        std::string msgStr = "Parameter error. The type of \"authTrustLevel\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    uint32_t authTrustLevel;
    ret = UserAuthNapiHelper::GetUint32Value(env, value, authTrustLevel);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint32Value fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"authTrustLevel\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    if (!UserAuthHelper::CheckAuthTrustLevel(authTrustLevel)) {
        IAM_LOGE("AuthTrustLevel fail:%{public}u", authTrustLevel);
        return UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT;
    }
    authParam.authTrustLevel = AuthTrustLevel(authTrustLevel);
    IAM_LOGI("authTrustLevel:%{public}u", authParam.authTrustLevel);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitReuseUnlockResult(napi_env env, napi_value value, AuthParamInner &authParam)
{
    uint32_t reuseMode;
    uint32_t reuseDuration;
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, REUSEMODE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", REUSEMODE.c_str());
        std::string msgStr = "Parameter error. \"reuseMode\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_reuseMode = UserAuthNapiHelper::GetNamedProperty(env, value, REUSEMODE);
    napi_status ret = UserAuthNapiHelper::GetUint32Value(env, napi_reuseMode, reuseMode);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint32Value fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"reuseMode\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    authParam.reuseUnlockResult.reuseMode = ReuseMode(reuseMode);
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, REUSEDURATION)) {
        IAM_LOGE("propertyName: %{public}s not exists.", REUSEDURATION.c_str());
        std::string msgStr = "Parameter error. \"reuseDuration\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_reuseDuration = UserAuthNapiHelper::GetNamedProperty(env, value, REUSEDURATION);
    ret = UserAuthNapiHelper::GetUint32Value(env, napi_reuseDuration, reuseDuration);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint32Value fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"reuseDuration\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    authParam.reuseUnlockResult.reuseDuration = reuseDuration;
    if (!UserAuthHelper::CheckReuseUnlockResult(authParam.reuseUnlockResult)) {
        IAM_LOGE("ReuseUnlockResult fail");
        std::string msgStr = "Parameter error. The type of \"reuseUnlockResult\" must be ReuseUnlockResult.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    authParam.reuseUnlockResult.isReuse = true;
    IAM_LOGI("reuseMode: %{public}u, reuseDuration: %{public}" PRIu64, authParam.reuseUnlockResult.reuseMode,
        authParam.reuseUnlockResult.reuseDuration);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitUserId(napi_env env, napi_value value, AuthParamInner &authParam)
{
    napi_status ret = UserAuthNapiHelper::GetInt32Value(env, value, authParam.userId);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint32Value fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"userId\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    if (authParam.userId < 0) {
        IAM_LOGE("GetInt32Value fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The \"userId\" must be greater than or equal to 0";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    authParam.isUserIdSpecified = true;
    IAM_LOGI("InitUserId userId: %{public}d", authParam.userId);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessUserId(napi_env env, napi_value value, AuthParamInner &authParam)
{
    if (UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_USER_ID)) {
        napi_value napi_userId = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_USER_ID);
        UserAuthResultCode errorCode = InitUserId(env, napi_userId, authParam);
        if (errorCode != UserAuthResultCode::SUCCESS) {
            IAM_LOGE("InitUserId fail:%{public}d", errorCode);
            return errorCode;
        }
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitAuthParam(napi_env env, napi_value value, AuthParamInner &authParam)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("authParam is null");
        std::string msgStr = "Parameter error. \"authParam\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    UserAuthResultCode errorCode = InitMandatoryAuthParam(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    errorCode = InitOptionalAuthParam(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitMandatoryAuthParam(napi_env env, napi_value value,
    AuthParamInner &authParam)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_CHALLENGE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_CHALLENGE.c_str());
        std::string msgStr = "Parameter error. \"challenge\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_challenge = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_CHALLENGE);
    UserAuthResultCode errorCode = InitChallenge(env, napi_challenge, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitChallenge fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_AUTHTYPE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_AUTHTYPE.c_str());
        std::string msgStr = "Parameter error. \"authType\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_authType = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_AUTHTYPE);
    errorCode = InitAuthType(env, napi_authType, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthType fail:%{public}d", errorCode);
        return errorCode;
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_AUTHTRUSTLEVEL)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_AUTHTRUSTLEVEL.c_str());
        std::string msgStr = "Parameter error. \"authTrustLevel\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_authTrustLevel = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_AUTHTRUSTLEVEL);
    errorCode = InitAuthTrustLevel(env, napi_authTrustLevel, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthTrustLevel fail:%{public}d", errorCode);
    }
    return errorCode;
}

UserAuthResultCode UserAuthParamUtils::InitOptionalAuthParam(napi_env env, napi_value value,
    AuthParamInner &authParam)
{
    UserAuthResultCode errorCode = ProcessReuseUnlockResult(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("ProcessReuseUnlockResult fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = ProcessUserId(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("ProcessUserId fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = ProcessSkipLockedBiometricAuth(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("ProcessSkipLockedBiometricAuth fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = ProcessCredentialIdList(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("ProcessCredentialIdList fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = ProcessAuthIntent(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("ProcessAuthIntent fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = ProcessRemoteAuthOptions(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("ProcessRemoteAuthOptions fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = ProcessAdditionalInfo(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("ProcessAdditionalInfo fail:%{public}d", errorCode);
        return errorCode;
    }
    return ProcessScheduledAuthTokenOptions(env, value, authParam);
}

UserAuthResultCode UserAuthParamUtils::ProcessReuseUnlockResult(napi_env env, napi_value value,
    AuthParamInner &authParam)
{
    if (UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_REUSEUNLOCKRESULT)) {
        napi_value napi_reuseUnlockResult = UserAuthNapiHelper::GetNamedProperty(env, value,
            AUTH_PARAM_REUSEUNLOCKRESULT);
        UserAuthResultCode errorCode = InitReuseUnlockResult(env, napi_reuseUnlockResult, authParam);
        if (errorCode != UserAuthResultCode::SUCCESS) {
            IAM_LOGE("InitReuseUnlockResult fail:%{public}d", errorCode);
            return errorCode;
        }
    } else {
        authParam.reuseUnlockResult.isReuse = false;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitWidgetParam(napi_env env, napi_value value,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt,
    std::shared_ptr<AbilityRuntime::Context> &abilityContext, sptr<OHOS::Rosen::Window> &window)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGE("widgetParam is null");
        std::string msgStr = "Parameter error. \"widgetParam\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_TITLE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", WIDGET_PARAM_TITLE.c_str());
        std::string msgStr = "Parameter error. \"title\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    std::string title = UserAuthNapiHelper::GetStringPropertyUtf8(env, value, WIDGET_PARAM_TITLE);
    if (title == "" || UserAuthHelper::GetUtf8CharCount(title) > TITLE_MAX) {
        IAM_LOGE("title is invalid. size: %{public}zu", UserAuthHelper::GetUtf8CharCount(title));
        std::string msgStr = "Parameter error. The length of \"title\" connot exceed 500.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    widgetParamExt.title = title;

    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_NAVIBTNTEXT)) {
        std::string naviBtnTxt = UserAuthNapiHelper::GetStringPropertyUtf8(env, value, WIDGET_PARAM_NAVIBTNTEXT);
        if (naviBtnTxt == "" || UserAuthHelper::GetUtf8CharCount(naviBtnTxt) > WidgetType::BUTTON_MAX) {
            IAM_LOGE("navigation button text is invalid, size: %{public}zu",
                UserAuthHelper::GetUtf8CharCount(naviBtnTxt));
            std::string msgStr = "Parameter error. The length of \"navigationButtonText\" connot exceed 60.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
        widgetParamExt.navigationButtonText = naviBtnTxt;
    }

    UserAuthResultCode errorCode = ProcessWindowMode(env, value, widgetParamExt);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }

    // appWindow is system-api-only and never crosses IPC; reject non-system callers here.
    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_WINDOW) &&
        !UserAuthNapiHelper::IsSystemApiCaller()) {
        IAM_LOGE("appWindow used by non-system caller");
        std::string msgStr = "Permission denied. \"appWindow\" is a system api only parameter.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED, msgStr);
    }

    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_CONTEXT)) {
        errorCode = ProcessContext(env, value, widgetParamExt, abilityContext);
    } else if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_WINDOW)) {
        errorCode = ProcessWindow(env, value, widgetParamExt, window);
    }
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGI("context or window is invalid");
        return errorCode;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessContext(napi_env env, napi_value value,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt,
    std::shared_ptr<AbilityRuntime::Context> &abilityContext)
{
    IAM_LOGI("process uiContext");
    napi_value napi_uiContext = UserAuthNapiHelper::GetNamedProperty(env, value, WIDGET_PARAM_CONTEXT);
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, napi_uiContext, napi_object);
    if (ret != napi_ok) {
        IAM_LOGE("get uiContext fail: %{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"uiContext\" must be context.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    bool stageMode = false;
    ret = OHOS::AbilityRuntime::IsStageContext(env, napi_uiContext, stageMode);
    if (ret != napi_ok || !stageMode) {
        IAM_LOGE("uiContext must be stage mode: %{public}d, stageMode: %{public}d", ret, stageMode);
        std::string msgStr = "Parameter error. The type of \"uiContext\" must be stage mode.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, napi_uiContext);
    if (CheckUIContext(context)) {
        abilityContext = context;
        widgetParamExt.hasContext = true;
        IAM_LOGI("widgetParamExt has valid uiContext");
    } else {
        // Default as modal system
        IAM_LOGI("widgetParamExt has invalid uiContext, not base on valid AbilityContext or UIExtensionContext.");
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessWindow(napi_env env, napi_value value,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt, sptr<OHOS::Rosen::Window> &window)
{
    IAM_LOGI("process window");
    napi_value napi_window = UserAuthNapiHelper::GetNamedProperty(env, value, WIDGET_PARAM_WINDOW);
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, napi_window, napi_object);
    if (ret != napi_ok) {
        IAM_LOGE("get window fail: %{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"window\" must be window.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    OHOS::Rosen::JsWindow *nativeWindow = nullptr;
    ret = napi_unwrap(env, napi_window, reinterpret_cast<void**>(&nativeWindow));
    if (ret != napi_ok || nativeWindow == nullptr) {
        IAM_LOGE("unwrap window fail: %{public}d", ret);
        std::string msgStr = "Parameter error. Failed to unwrap window object.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    window = nativeWindow->GetWindow();
    widgetParamExt.hasContext = true;
    IAM_LOGI("widgetParamExt has valid window");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessWindowMode(napi_env env, napi_value value,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt)
{
    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_WINDOWMODE)) {
        napi_value napi_windowModeType = UserAuthNapiHelper::GetNamedProperty(env, value, WIDGET_PARAM_WINDOWMODE);
        uint32_t windowMode;
        napi_status ret = UserAuthNapiHelper::GetUint32Value(env, napi_windowModeType, windowMode);
        if (ret != napi_ok) {
            IAM_LOGE("napi authType GetUint32Value fail:%{public}d", ret);
            std::string msgStr = "Parameter error. The type of \"windowMode\" must be number.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
        switch (windowMode) {
            case WindowModeType::DIALOG_BOX:
            case WindowModeType::FULLSCREEN:
            case WindowModeType::NONE_INTERRUPTION_DIALOG_BOX:
                widgetParamExt.windowMode = static_cast<WindowModeType>(windowMode);
                break;
            default:
                IAM_LOGE("windowMode type not support.");
                std::string msgStr = "Parameter error. The type of \"windowMode\" must be WindowModeType.";
                return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
    }

    IAM_LOGI("widgetParamExt title:%{public}s, navBtnText:%{public}s, winMode:%{public}u",
        widgetParamExt.title.c_str(), widgetParamExt.navigationButtonText.c_str(),
        static_cast<uint32_t>(widgetParamExt.windowMode));
    return UserAuthResultCode::SUCCESS;
}

bool UserAuthParamUtils::CheckUIContext(const std::shared_ptr<AbilityRuntime::Context> context)
{
    if (context == nullptr) {
        IAM_LOGE("get context failed");
        return false;
    }

    auto abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        IAM_LOGE("abilityContext is null");
        auto holderContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIHolderExtensionContext>(context);
        if (holderContext == nullptr) {
            IAM_LOGE("uiExtensionContext is null");
            return false;
        }
        if (holderContext->GetUIContent() == nullptr) {
            IAM_LOGE("uiContent is null");
            return false;
        }
    } else {
        if (abilityContext->GetUIContent() == nullptr) {
            IAM_LOGE("uiContent is null");
            return false;
        }
    }
    return true;
}

UserAuthResultCode UserAuthParamUtils::ProcessSkipLockedBiometricAuth(napi_env env, napi_value value,
    AuthParamInner &authParam)
{
    if (UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_SKIP_LOCKED_BIOMETRIC_AUTH)) {
        napi_value skipLockedBiometricAuth = UserAuthNapiHelper::GetNamedProperty(env, value,
            AUTH_PARAM_SKIP_LOCKED_BIOMETRIC_AUTH);
        napi_status ret = UserAuthNapiHelper::GetBoolValue(env, skipLockedBiometricAuth,
            authParam.skipLockedBiometricAuth);
        if (ret != napi_ok) {
            IAM_LOGE("GetBoolValue fail:%{public}d", ret);
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        IAM_LOGI("Init skipLockedBiometricAuth: %{public}d", authParam.skipLockedBiometricAuth);
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessCredentialIdList(napi_env env, napi_value value,
    AuthParamInner &authParam)
{
    if (UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_CREDENTIAL_ID_LIST)) {
        napi_value credentialIdList = UserAuthNapiHelper::GetNamedProperty(env, value,
            AUTH_PARAM_CREDENTIAL_ID_LIST);
        uint32_t outSize = 0;
        if (!UserAuthNapiHelper::ConvertSizeToUint32(MAX_CREDENTIAL_ID_LIST_SIZE, outSize)) {
            IAM_LOGE("ConvertSizeToUint32 fail");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        napi_status ret = UserAuthNapiHelper::GetUint64VectorFromUint8ArrayArrayValue(env, credentialIdList,
            outSize, authParam.credentialIdList);
        if (ret != napi_ok) {
            IAM_LOGE("GetUint64VectorFromUint8ArrayArrayValue fail:%{public}d", ret);
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        IAM_LOGI("Init credentialIdList.size(): %{public}zu", authParam.credentialIdList.size());
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessAuthIntent(napi_env env, napi_value value, AuthParamInner &authParam)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_AUTH_INTENT)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_value authIntentValue = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_AUTH_INTENT);
    int32_t intent = 0;
    napi_status ret = UserAuthNapiHelper::GetInt32Value(env, authIntentValue, intent);
    if (ret != napi_ok) {
        IAM_LOGE("GetInt32Value fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"authIntent\" must be AuthIntent.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    if (intent < static_cast<int32_t>(AuthIntent::UNLOCK) ||
        intent > static_cast<int32_t>(AuthIntent::SUDO_PIN_AUTH)) {
        IAM_LOGE("invalid authIntent:%{public}d", intent);
        std::string msgStr = "Parameter error. The value of \"authIntent\" is out of range.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    authParam.authIntent = static_cast<AuthIntent>(intent);
    IAM_LOGI("Init authIntent: %{public}d", intent);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessRemoteNetworkId(napi_env env, napi_value remoteValue,
    const std::string &propertyName, std::optional<std::string> &networkId)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, remoteValue, propertyName)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_value networkIdValue = UserAuthNapiHelper::GetNamedProperty(env, remoteValue, propertyName);
    if (IsNullOrUndefined(env, networkIdValue)) {
        return UserAuthResultCode::SUCCESS;
    }
    if (UserAuthNapiHelper::CheckNapiType(env, networkIdValue, napi_string) != napi_ok) {
        IAM_LOGE("%{public}s is not a string", propertyName.c_str());
        std::string msgStr = "Parameter error. The value of \"" + propertyName + "\" is invalid.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    std::string networkIdStr = UserAuthNapiHelper::GetStringFromValueUtf8(env, networkIdValue);
    if (networkIdStr.size() > RemoteLimit::MAX_NETWORK_ID_LEN) {
        IAM_LOGE("%{public}s len:%{public}zu", propertyName.c_str(), networkIdStr.size());
        std::string msgStr = "Parameter error. The value of \"" + propertyName + "\" is invalid.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    networkId = networkIdStr;
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessCollectorTokenId(napi_env env, napi_value remoteValue,
    RemoteAuthParam &remoteAuthParam)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, remoteValue, REMOTE_PARAM_COLLECTOR_TOKEN_ID)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_value tokenIdValue = UserAuthNapiHelper::GetNamedProperty(env, remoteValue,
        REMOTE_PARAM_COLLECTOR_TOKEN_ID);
    if (IsNullOrUndefined(env, tokenIdValue)) {
        return UserAuthResultCode::SUCCESS;
    }
    int32_t tokenId = 0;
    napi_status ret = UserAuthNapiHelper::GetInt32Value(env, tokenIdValue, tokenId);
    if (ret != napi_ok || tokenId < 0) {
        IAM_LOGE("collectorTokenId is invalid:%{public}d", tokenId);
        std::string msgStr = "Parameter error. The value of \"collectorTokenId\" is invalid.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    remoteAuthParam.collectorTokenId = static_cast<uint32_t>(tokenId);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessRemoteAuthOptions(napi_env env, napi_value value,
    AuthParamInner &authParam)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_REMOTE_AUTH_OPTIONS)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_value remoteValue = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_REMOTE_AUTH_OPTIONS);
    if (IsNullOrUndefined(env, remoteValue)) {
        IAM_LOGI("remoteAuthOptions is null");
        return UserAuthResultCode::SUCCESS;
    }
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, remoteValue, napi_object);
    if (ret != napi_ok) {
        IAM_LOGE("CheckNapiType fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"remoteAuthOptions\" must be RemoteAuthOptions.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    RemoteAuthParam remoteAuthParam = {};
    UserAuthResultCode errorCode = ProcessRemoteNetworkId(env, remoteValue, REMOTE_PARAM_VERIFIER_NETWORK_ID,
        remoteAuthParam.verifierNetworkId);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    errorCode = ProcessRemoteNetworkId(env, remoteValue, REMOTE_PARAM_COLLECTOR_NETWORK_ID,
        remoteAuthParam.collectorNetworkId);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    errorCode = ProcessCollectorTokenId(env, remoteValue, remoteAuthParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    authParam.remoteAuthParam = remoteAuthParam;
    if (!remoteAuthParam.verifierNetworkId.has_value() && !remoteAuthParam.collectorNetworkId.has_value() &&
        !remoteAuthParam.collectorTokenId.has_value()) {
        IAM_LOGI("remoteAuthOptions has no effective field, treat as absent");
        authParam.remoteAuthParam = std::nullopt;
        return UserAuthResultCode::SUCCESS;
    }
    IAM_LOGI("Init remoteAuthOptions, verifierHasValue:%{public}s, collectorHasValue:%{public}s, "
        "tokenIdHasValue:%{public}s",
        remoteAuthParam.verifierNetworkId.has_value() ? "true" : "false",
        remoteAuthParam.collectorNetworkId.has_value() ? "true" : "false",
        remoteAuthParam.collectorTokenId.has_value() ? "true" : "false");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessAdditionalInfo(napi_env env, napi_value value,
    AuthParamInner &authParam)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_ADDITIONAL_INFO)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_value additionalInfoValue = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_ADDITIONAL_INFO);
    if (IsNullOrUndefined(env, additionalInfoValue)) {
        IAM_LOGI("additionalInfo is null");
        return UserAuthResultCode::SUCCESS;
    }
    if (UserAuthNapiHelper::CheckNapiType(env, additionalInfoValue, napi_string) != napi_ok) {
        IAM_LOGE("additionalInfo is not a string");
        std::string msgStr = "Parameter error. The value of \"additionalInfo\" is invalid.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    std::string additionalInfo = UserAuthNapiHelper::GetStringFromValueUtf8(env, additionalInfoValue);
    if (UserAuthHelper::GetUtf8CharCount(additionalInfo) > static_cast<size_t>(ADDITIONAL_INFO_MAX)) {
        IAM_LOGE("additionalInfo len:%{public}zu", additionalInfo.size());
        std::string msgStr = "Parameter error. The length of \"additionalInfo\" cannot exceed 10000.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    authParam.additionalInfo = additionalInfo;
    IAM_LOGI("Init additionalInfo, len:%{public}zu", additionalInfo.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ReadMandatoryInt64Field(napi_env env, napi_value value,
    const std::string &propertyName, int64_t &out)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, propertyName)) {
        IAM_LOGE("mandatory field %{public}s not exists", propertyName.c_str());
        std::string msgStr = "Parameter error. \"" + propertyName + "\" is a mandatory parameter.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value fieldValue = UserAuthNapiHelper::GetNamedProperty(env, value, propertyName);
    napi_status ret = napi_get_value_int64(env, fieldValue, &out);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_value_int64 fail:%{public}d, field:%{public}s", ret, propertyName.c_str());
        std::string msgStr = "Parameter error. The value of \"" + propertyName + "\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ReadOptionalInt64Field(napi_env env, napi_value value,
    const std::string &propertyName, bool &hasValue, int64_t &out)
{
    hasValue = false;
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, propertyName)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_value fieldValue = UserAuthNapiHelper::GetNamedProperty(env, value, propertyName);
    if (IsNullOrUndefined(env, fieldValue)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_status ret = napi_get_value_int64(env, fieldValue, &out);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_value_int64 fail:%{public}d, field:%{public}s", ret, propertyName.c_str());
        std::string msgStr = "Parameter error. The value of \"" + propertyName + "\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    hasValue = true;
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ReadWindowConfig(napi_env env, napi_value scheduleValue,
    std::optional<RedemptionWindow> &windowConfig)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, scheduleValue, SCHEDULE_PARAM_WINDOW_CONFIG)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_value windowConfigValue = UserAuthNapiHelper::GetNamedProperty(env, scheduleValue,
        SCHEDULE_PARAM_WINDOW_CONFIG);
    if (IsNullOrUndefined(env, windowConfigValue)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, windowConfigValue, napi_object);
    if (ret != napi_ok) {
        IAM_LOGE("CheckNapiType fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"windowConfig\" must be RedemptionWindow.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    RedemptionWindow window = {};
    UserAuthResultCode errorCode = ReadMandatoryInt64Field(env, windowConfigValue,
        SCHEDULE_PARAM_REPEAT_INTERVAL, window.repeatInterval);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    errorCode = ReadMandatoryInt64Field(env, windowConfigValue, SCHEDULE_PARAM_WINDOW_DURATION,
        window.windowDuration);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    windowConfig = window;
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessScheduledAuthTokenOptions(napi_env env, napi_value value,
    AuthParamInner &authParam)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_SCHEDULED_AUTH_TOKEN_OPTIONS)) {
        return UserAuthResultCode::SUCCESS;
    }
    napi_value scheduleValue = UserAuthNapiHelper::GetNamedProperty(env, value,
        AUTH_PARAM_SCHEDULED_AUTH_TOKEN_OPTIONS);
    if (IsNullOrUndefined(env, scheduleValue)) {
        IAM_LOGI("scheduledAuthTokenOptions is null");
        return UserAuthResultCode::SUCCESS;
    }
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, scheduleValue, napi_object);
    if (ret != napi_ok) {
        IAM_LOGE("CheckNapiType fail:%{public}d", ret);
        std::string msgStr =
            "Parameter error. The type of \"scheduledAuthTokenOptions\" must be TokenRedemptionSchedule.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    TokenSchedule schedule = {};
    UserAuthResultCode errorCode = ReadWindowConfig(env, scheduleValue, schedule.windowConfig);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    errorCode = ReadOptionalInt64Field(env, scheduleValue, SCHEDULE_PARAM_VALID_START_TIME,
        schedule.hasValidStartTime, schedule.validStartTime);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    errorCode = ReadOptionalInt64Field(env, scheduleValue, SCHEDULE_PARAM_VALID_END_TIME,
        schedule.hasValidEndTime, schedule.validEndTime);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    std::string scheduleErrorDesc;
    if (UserAuthHelper::CheckTokenSchedule(schedule, scheduleErrorDesc) != SUCCESS) {
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, scheduleErrorDesc);
    }
    authParam.tokenSchedule = schedule;
    IAM_LOGI("Init scheduledAuthTokenOptions: %{public}s",
        UserAuthHelper::TokenScheduleToString(schedule).c_str());
    return UserAuthResultCode::SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

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

#include "foundation/window/window_manager/interfaces/kits/napi/window_runtime/window_napi/js_window.h"
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
    IAM_LOGI("InitUserId userId: %{public}d", authParam.userId);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessAuthTrustLevelAndUserId(napi_env env, napi_value value,
    AuthParamInner &authParam)
{
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_AUTHTRUSTLEVEL)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_AUTHTRUSTLEVEL.c_str());
        std::string msgStr = "Parameter error. \"authTrustLevel\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_authTrustLevel = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_AUTHTRUSTLEVEL);
    UserAuthResultCode errorCode = InitAuthTrustLevel(env, napi_authTrustLevel, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthTrustLevel fail:%{public}d", errorCode);
        return errorCode;
    }

    if (UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_USER_ID)) {
        napi_value napi_userId = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_USER_ID);
        errorCode = InitUserId(env, napi_userId, authParam);
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

    errorCode = ProcessReuseUnlockResult(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    errorCode = ProcessAuthTrustLevelAndUserId(env, value, authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("ProcessAuthTrustLevelAndUserId fail:%{public}d", errorCode);
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
    return UserAuthResultCode::SUCCESS;
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
    WidgetParamNapi &widgetParam, std::shared_ptr<AbilityRuntime::Context> &abilityContext,
    sptr<OHOS::Rosen::Window> &window)
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
    widgetParam.title = title;

    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_NAVIBTNTEXT)) {
        std::string naviBtnTxt = UserAuthNapiHelper::GetStringPropertyUtf8(env, value, WIDGET_PARAM_NAVIBTNTEXT);
        if (naviBtnTxt == "" || UserAuthHelper::GetUtf8CharCount(naviBtnTxt) > WidgetType::BUTTON_MAX) {
            IAM_LOGE("navigation button text is invalid, size: %{public}zu",
                UserAuthHelper::GetUtf8CharCount(naviBtnTxt));
            std::string msgStr = "Parameter error. The length of \"navigationButtonText\" connot exceed 60.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
        widgetParam.navigationButtonText = naviBtnTxt;
    }

    UserAuthResultCode errorCode = ProcessWindowMode(env, value, widgetParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }

    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_CONTEXT)) {
        errorCode = ProcessContext(env, value, widgetParam, abilityContext);
    } else if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_WINDOW)) {
        errorCode = ProcessWindow(env, value, widgetParam, window);
    }
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGI("context or window is invalid");
        return errorCode;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessContext(napi_env env, napi_value value,
    WidgetParamNapi &widgetParam, std::shared_ptr<AbilityRuntime::Context> &abilityContext)
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
    if (ret != napi_ok) {
        IAM_LOGE("uiContext must be stage mode: %{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"uiContext\" must be stage mode.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, napi_uiContext);
    if (CheckUIContext(context)) {
        abilityContext = context;
        widgetParam.hasContext = true;
        IAM_LOGI("widgetParam has valid uiContext");
    } else {
        // Default as modal system
        IAM_LOGI("widgetParam has invalid uiContext, not base on valid AbilityContext or UIExtensionContext.");
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessWindow(napi_env env, napi_value value,
    WidgetParamNapi &widgetParam, sptr<OHOS::Rosen::Window> &window)
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
    widgetParam.hasContext = true;
    IAM_LOGI("widgetParam has valid window");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::ProcessWindowMode(napi_env env, napi_value value,
    WidgetParamNapi &widgetParam)
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
                widgetParam.windowMode = static_cast<WindowModeType>(windowMode);
                break;
            default:
                IAM_LOGE("windowMode type not support.");
                std::string msgStr = "Parameter error. The type of \"windowMode\" must be WindowModeType.";
                return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
    }

    IAM_LOGI("widgetParam title:%{public}s, navBtnText:%{public}s, winMode:%{public}u",
        widgetParam.title.c_str(), widgetParam.navigationButtonText.c_str(),
        static_cast<uint32_t>(widgetParam.windowMode));
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
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

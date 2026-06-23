/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "taihe/runtime.hpp"
#include "ani_base_context.h"
#include "window.h"
#include "ui_content.h"
#include "ui_extension_context.h"
#include "ui_holder_extension_context.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "user_auth_common_defines.h"
#include "user_auth_helper.h"

#include "foundation/window/window_manager/interfaces/kits/ani/window_runtime/window_stage_ani/include/ani_window.h"

#define LOG_TAG "USER_AUTH_ANI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_PARAM_UTILS_ANI

namespace userAuth = ohos::userIAM::userAuth::userAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::string AUTH_EVENT_RESULT = "result";
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
const std::string NOTICETYPE = "noticeType";
const std::string REUSEMODE = "reuseMode";
const std::string REUSEDURATION = "reuseDuration";

namespace WidgetType {
constexpr int32_t BUTTON_MAX = 60;
}  // namespace WidgetType

UserAuthResultCode UserAuthParamUtils::InitAuthParam(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitAuthParam start");
    std::vector<uint8_t> challenge(authParam.challenge.begin(), authParam.challenge.end());
    authParamInner.challenge = challenge;

    UserAuthResultCode errorCode = InitAuthType(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthType fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitAuthTrustLevel(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthTrustLevel fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitReuseUnlockResult(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitReuseUnlockResult fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitUserId(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitUserId fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitSkipLockedBiometricAuth(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitSkipLockedBiometricAuth fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitCredentialIdList(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitCredentialIdList fail:%{public}d", errorCode);
        return errorCode;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitAuthType(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitAuthType start.");
    for (const auto &type : authParam.authType) {
        if (!UserAuthHelper::CheckUserAuthType(type)) {
            IAM_LOGE("authType is illegal, %{public}d", type.get_value());
            return UserAuthResultCode::TYPE_NOT_SUPPORT;
        }
        authParamInner.authTypes.push_back(static_cast<AuthType>(static_cast<std::int32_t>(type.get_value())));
    }
    IAM_LOGI("authType size:%{public}zu", authParamInner.authTypes.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitAuthTrustLevel(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitAuthTrustLevel start.");
    auto authTrustLevel = authParam.authTrustLevel;
    if (!UserAuthHelper::CheckAuthTrustLevel(authTrustLevel)) {
        IAM_LOGE("AuthTrustLevel fail:%{public}u", authTrustLevel.get_value());
        return UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT;
    }
    authParamInner.authTrustLevel = AuthTrustLevel(static_cast<int32_t>(authTrustLevel));
    IAM_LOGI("authTrustLevel:%{public}u", authParamInner.authTrustLevel);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitReuseUnlockResult(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitReuseUnlockResult start.");
    if (authParam.reuseUnlockResult.has_value()) {
        authParamInner.reuseUnlockResult.isReuse = true;
        authParamInner.reuseUnlockResult.reuseMode =
            ReuseMode(static_cast<int32_t>(authParam.reuseUnlockResult->reuseMode.get_value()));
        authParamInner.reuseUnlockResult.reuseDuration = authParam.reuseUnlockResult->reuseDuration;
        if (!UserAuthHelper::CheckReuseUnlockResult(authParamInner.reuseUnlockResult)) {
            IAM_LOGE("ReuseUnlockResult fail");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        IAM_LOGI("reuseMode: %{public}u, reuseDuration: %{public}" PRIu64,
                 authParamInner.reuseUnlockResult.reuseMode,
                 authParamInner.reuseUnlockResult.reuseDuration);
    } else {
        IAM_LOGI("propertyName: %{public}s not exists.", AUTH_PARAM_REUSEUNLOCKRESULT.c_str());
        authParamInner.reuseUnlockResult.isReuse = false;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitUserId(userAuth::AuthParam const &authParam, AuthParamInner &authParamInner)
{
    IAM_LOGI("InitUserId start.");
    if (authParam.userId.has_value()) {
        authParamInner.userId = authParam.userId.value();
        authParamInner.isUserIdSpecified = true;
        if (authParamInner.userId < 0) {
            IAM_LOGE("userId error.");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        IAM_LOGI("InitUserId userId: %{public}d", authParamInner.userId);
    } else {
        IAM_LOGI("propertyName: %{public}s not exists.", AUTH_PARAM_USER_ID.c_str());
        authParamInner.isUserIdSpecified = false;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitSkipLockedBiometricAuth(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitSkipLockedBiometricAuth start.");
    if (authParam.skipLockedBiometricAuth.has_value()) {
        authParamInner.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth.value();
        IAM_LOGI("InitSkipLockedBiometricAuth value: %{public}d", authParamInner.skipLockedBiometricAuth);
    } else {
        IAM_LOGI("propertyName: %{public}s not exists.", AUTH_PARAM_SKIP_LOCKED_BIOMETRIC_AUTH.c_str());
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitCredentialIdList(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitCredentialIdList start.");
    if (!authParam.credentialIdList.has_value()) {
        IAM_LOGI("propertyName: %{public}s not exists.", AUTH_PARAM_CREDENTIAL_ID_LIST.c_str());
        return UserAuthResultCode::SUCCESS;
    }
    auto credentialIdList = authParam.credentialIdList.value();
    if (credentialIdList.size() > MAX_CREDENTIAL_ID_LIST_SIZE) {
        IAM_LOGE("bad credentialIdList.size():%{public}zu", credentialIdList.size());
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    authParamInner.credentialIdList.clear();
    authParamInner.credentialIdList.reserve(credentialIdList.size());
    for (auto credentialId: credentialIdList) {
        if (credentialId.size() != (sizeof(uint64_t) / sizeof(uint8_t))) {
            IAM_LOGE("credentialId.size():%{public}zu", credentialId.size());
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        uint64_t dest = 0;
        if (memcpy_s(&dest, sizeof(uint64_t), credentialId.data(), sizeof(uint64_t)) != EOK) {
            IAM_LOGE("memcpy_s fail");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        authParamInner.credentialIdList.push_back(dest);
    }
    IAM_LOGI("InitCredentialIdList.size(): %{public}zu", authParamInner.credentialIdList.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitWidgetParam(userAuth::WidgetParam const &widgetParam,
    WidgetParamNapi &widgetParamNapi, std::shared_ptr<AbilityRuntime::Context> &abilityContext,
    sptr<OHOS::Rosen::Window> &window)
{
    IAM_LOGI("InitWidgetParam start.");
    UserAuthResultCode errorCode = InitTitle(widgetParam, widgetParamNapi);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitTitle fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    errorCode = InitNavigationButtonText(widgetParam, widgetParamNapi);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitNavigationButtonText fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    errorCode = InitWindowMode(widgetParam, widgetParamNapi);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitWindowMode fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    if (widgetParam.uiContext.has_value()) {
        IAM_LOGI("widgetParam has uiContext");
        errorCode = InitContext(widgetParam, widgetParamNapi, abilityContext);
        if (errorCode != UserAuthResultCode::SUCCESS) {
            IAM_LOGE("InitContext fail:%{public}d", errorCode);
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
    } else if (widgetParam.appWindow.has_value()) {
        IAM_LOGI("widgetParam has window");
        errorCode = InitWindow(widgetParam, widgetParamNapi, window);
        if (errorCode != UserAuthResultCode::SUCCESS) {
            IAM_LOGE("InitWindow fail:%{public}d", errorCode);
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitTitle(userAuth::WidgetParam const &widgetParam,
    WidgetParamNapi &widgetParamNapi)
{
    IAM_LOGI("InitTitle start.");
    std::string title = widgetParam.title.c_str();
    if (title == "" || UserAuthHelper::GetUtf8CharCount(title) > TITLE_MAX) {
        IAM_LOGE("title is invalid. size: %{public}zu", UserAuthHelper::GetUtf8CharCount(title));
        std::string msgStr = "Parameter error. The length of \"title\" connot exceed 500.";
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    widgetParamNapi.title = title;
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitNavigationButtonText(userAuth::WidgetParam const &widgetParam,
    WidgetParamNapi &widgetParamNapi)
{
    IAM_LOGI("InitNavigationButtonText start.");
    if (widgetParam.navigationButtonText.has_value()) {
        std::string naviBtnTxt = widgetParam.navigationButtonText->c_str();
        if (naviBtnTxt == "" || UserAuthHelper::GetUtf8CharCount(naviBtnTxt) > WidgetType::BUTTON_MAX) {
            IAM_LOGE("navigation button text is invalid, size: %{public}zu",
                UserAuthHelper::GetUtf8CharCount(naviBtnTxt));
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        widgetParamNapi.navigationButtonText = naviBtnTxt;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitWindowMode(userAuth::WidgetParam const &widgetParam,
    WidgetParamNapi &widgetParamNapi)
{
    IAM_LOGI("InitWindowMode start.");
    if (widgetParam.windowMode.has_value()) {
        switch (widgetParam.windowMode->get_key()) {
            case userAuth::WindowModeType::key_t::DIALOG_BOX:
                widgetParamNapi.windowMode = WindowModeType::DIALOG_BOX;
                break;
            case userAuth::WindowModeType::key_t::FULLSCREEN:
                widgetParamNapi.windowMode = WindowModeType::FULLSCREEN;
                break;
            default:
                IAM_LOGE("windowMode type not support.");
                return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        IAM_LOGI("widgetParam title:%{public}s, navBtnText:%{public}s, winMode:%{public}u",
            widgetParamNapi.title.c_str(),
            widgetParamNapi.navigationButtonText.c_str(),
            static_cast<uint32_t>(widgetParamNapi.windowMode));
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitContext(userAuth::WidgetParam const &widgetParam,
    WidgetParamNapi &widgetParamNapi, std::shared_ptr<AbilityRuntime::Context> &abilityContext)
{
    IAM_LOGI("InitContext start.");
    ani_env *env = taihe::get_env();
    ani_object uiContext = reinterpret_cast<ani_object>(widgetParam.uiContext.value());
    ani_boolean stageMode = false;
    ani_status status = OHOS::AbilityRuntime::IsStageContext(env, uiContext, stageMode);
    if (status != ANI_OK) {
        IAM_LOGE("uiContext must be stage mode: %{public}d", status);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, uiContext);
    if (CheckUIContext(context)) {
        abilityContext = context;
        widgetParamNapi.hasContext = true;
        IAM_LOGI("widgetParam has valid uiContext");
    } else {
        // Default as modal system
        IAM_LOGI("widgetParam has invalid uiContext, not base on valid AbilityContext or UIExtensionContext.");
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitWindow(userAuth::WidgetParam const &widgetParam,
    WidgetParamNapi &widgetParamNapi, sptr<OHOS::Rosen::Window> &window)
{
    IAM_LOGI("InitWindow start");
    ani_env *env = taihe::get_env();
    OHOS::Rosen::AniWindow *aniWindow = Rosen::AniWindow::GetWindowObjectFromEnv(env,
        reinterpret_cast<ani_object>(widgetParam.appWindow.value()));
    if (aniWindow == nullptr) {
        IAM_LOGE("get window object from env failed");
        return UserAuthResultCode::FAIL;
    }
    window = aniWindow->GetWindow();
    widgetParamNapi.hasContext = true;
    IAM_LOGI("widgetParam has valid window");
    return UserAuthResultCode::SUCCESS;
}

bool UserAuthParamUtils::CheckUIContext(const std::shared_ptr<OHOS::AbilityRuntime::Context> context)
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
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

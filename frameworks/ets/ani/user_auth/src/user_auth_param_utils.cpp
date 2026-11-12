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
#include "user_auth_ani_helper.h"

#include "ani_window.h"

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
constexpr uint32_t BITS_PER_BYTE = 8;

namespace WidgetType {
constexpr int32_t BUTTON_MAX = 60;
}  // namespace WidgetType

namespace RemoteLimit {
constexpr size_t MAX_NETWORK_ID_LEN = 64;
}  // namespace RemoteLimit

UserAuthResultCode UserAuthParamUtils::InitAuthParam(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitAuthParam start");
    UserAuthResultCode errorCode = InitMandatoryAuthParam(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    errorCode = InitOptionalAuthParam(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitMandatoryAuthParam(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    std::vector<uint8_t> challenge(authParam.challenge.begin(), authParam.challenge.end());
    if (challenge.size() > MAX_CHALLENG_LEN) {
        IAM_LOGE("challenge len %{public}zu", challenge.size());
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    authParamInner.challenge = challenge;
    UserAuthResultCode errorCode = InitAuthType(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthType fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = InitAuthTrustLevel(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthTrustLevel fail:%{public}d", errorCode);
    }
    return errorCode;
}

UserAuthResultCode UserAuthParamUtils::InitOptionalAuthParam(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    UserAuthResultCode errorCode = InitReuseUnlockResult(authParam, authParamInner);
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
    errorCode = InitAuthIntent(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthIntent fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = InitRemoteAuthOptions(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitRemoteAuthOptions fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = InitAdditionalInfo(authParam, authParamInner);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAdditionalInfo fail:%{public}d", errorCode);
        return errorCode;
    }
    return InitScheduledAuthTokenOptions(authParam, authParamInner);
}

UserAuthResultCode UserAuthParamUtils::InitAuthIntent(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitAuthIntent start.");
    if (!authParam.authIntent.has_value()) {
        return UserAuthResultCode::SUCCESS;
    }
    switch (authParam.authIntent->get_key()) {
        case userAuth::AuthIntent::key_t::UNLOCK:
            authParamInner.authIntent = AuthIntent::UNLOCK;
            break;
        case userAuth::AuthIntent::key_t::SILENT_AUTH:
            authParamInner.authIntent = AuthIntent::SILENT_AUTH;
            break;
        case userAuth::AuthIntent::key_t::QUESTION_AUTH:
            authParamInner.authIntent = AuthIntent::QUESTION_AUTH;
            break;
        case userAuth::AuthIntent::key_t::ABANDONED_PIN_AUTH:
            authParamInner.authIntent = AuthIntent::ABANDONED_PIN_AUTH;
            break;
        case userAuth::AuthIntent::key_t::SUDO_PIN_AUTH:
            authParamInner.authIntent = AuthIntent::SUDO_PIN_AUTH;
            break;
        default:
            IAM_LOGE("invalid authIntent");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    IAM_LOGI("authIntent: %{public}d", static_cast<int32_t>(authParamInner.authIntent));
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitRemoteAuthOptions(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitRemoteAuthOptions start.");
    if (!authParam.remoteAuthOptions.has_value()) {
        return UserAuthResultCode::SUCCESS;
    }
    RemoteAuthParam remoteAuthParam = {};
    if (authParam.remoteAuthOptions->verifierNetworkId.has_value()) {
        std::string verifierNetworkId = authParam.remoteAuthOptions->verifierNetworkId->c_str();
        if (verifierNetworkId.size() > RemoteLimit::MAX_NETWORK_ID_LEN) {
            IAM_LOGE("verifierNetworkId len:%{public}zu", verifierNetworkId.size());
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        remoteAuthParam.verifierNetworkId = verifierNetworkId;
    }
    if (authParam.remoteAuthOptions->collectorNetworkId.has_value()) {
        std::string collectorNetworkId = authParam.remoteAuthOptions->collectorNetworkId->c_str();
        if (collectorNetworkId.size() > RemoteLimit::MAX_NETWORK_ID_LEN) {
            IAM_LOGE("collectorNetworkId len:%{public}zu", collectorNetworkId.size());
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        remoteAuthParam.collectorNetworkId = collectorNetworkId;
    }
    if (authParam.remoteAuthOptions->collectorTokenId.has_value()) {
        if (authParam.remoteAuthOptions->collectorTokenId.value() < 0) {
            IAM_LOGE("collectorTokenId error");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        remoteAuthParam.collectorTokenId =
            static_cast<uint32_t>(authParam.remoteAuthOptions->collectorTokenId.value());
    }
    authParamInner.remoteAuthParam = remoteAuthParam;
    if (!remoteAuthParam.verifierNetworkId.has_value() && !remoteAuthParam.collectorNetworkId.has_value() &&
        !remoteAuthParam.collectorTokenId.has_value()) {
        IAM_LOGI("remoteAuthOptions has no effective field, treat as absent");
        authParamInner.remoteAuthParam = std::nullopt;
    }
    IAM_LOGI("InitRemoteAuthOptions done");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitAdditionalInfo(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitAdditionalInfo start.");
    if (!authParam.additionalInfo.has_value()) {
        return UserAuthResultCode::SUCCESS;
    }
    std::string additionalInfo = authParam.additionalInfo->c_str();
    if (UserAuthHelper::GetUtf8CharCount(additionalInfo) > static_cast<size_t>(ADDITIONAL_INFO_MAX)) {
        IAM_LOGE("additionalInfo len:%{public}zu", additionalInfo.size());
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    authParamInner.additionalInfo = additionalInfo;
    IAM_LOGI("additionalInfo len:%{public}zu", additionalInfo.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitScheduledAuthTokenOptions(userAuth::AuthParam const &authParam,
    AuthParamInner &authParamInner)
{
    IAM_LOGI("InitScheduledAuthTokenOptions start.");
    if (!authParam.scheduledAuthTokenOptions.has_value()) {
        return UserAuthResultCode::SUCCESS;
    }
    const userAuth::TokenRedemptionSchedule &schedule = authParam.scheduledAuthTokenOptions.value();
    TokenSchedule tokenSchedule = {};
    tokenSchedule.hasValidStartTime = schedule.validStartTime.has_value();
    if (tokenSchedule.hasValidStartTime) {
        tokenSchedule.validStartTime = schedule.validStartTime.value();
    }
    tokenSchedule.hasValidEndTime = schedule.validEndTime.has_value();
    if (tokenSchedule.hasValidEndTime) {
        tokenSchedule.validEndTime = schedule.validEndTime.value();
    }
    if (schedule.windowConfig.has_value()) {
        RedemptionWindow window = {};
        window.repeatInterval = schedule.windowConfig->repeatInterval;
        window.windowDuration = schedule.windowConfig->windowDuration;
        tokenSchedule.windowConfig = window;
    }
    authParamInner.tokenSchedule = tokenSchedule;
    IAM_LOGI("InitScheduledAuthTokenOptions done, hasValidStart:%{public}d, validStart:%{public}" PRId64
        ", hasValidEnd:%{public}d, validEnd:%{public}" PRId64,
        static_cast<int32_t>(tokenSchedule.hasValidStartTime), tokenSchedule.validStartTime,
        static_cast<int32_t>(tokenSchedule.hasValidEndTime), tokenSchedule.validEndTime);
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
        AuthType authType = static_cast<AuthType>(static_cast<std::int32_t>(type.get_value()));
        if (std::find(authParamInner.authTypes.begin(), authParamInner.authTypes.end(), authType) !=
            authParamInner.authTypes.end()) {
            IAM_LOGE("duplicate authType:%{public}d", type.get_value());
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        authParamInner.authTypes.push_back(authType);
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
        if (authParam.userId.value() < 0) {
            IAM_LOGE("userId error.");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        authParamInner.userId = authParam.userId.value();
        authParamInner.isUserIdSpecified = true;
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
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt,
    std::shared_ptr<AbilityRuntime::Context> &abilityContext, sptr<OHOS::Rosen::Window> &window)
{
    IAM_LOGI("InitWidgetParam start.");
    UserAuthResultCode errorCode = InitTitle(widgetParam, widgetParamExt);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitTitle fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    errorCode = InitNavigationButtonText(widgetParam, widgetParamExt);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitNavigationButtonText fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    errorCode = InitWindowMode(widgetParam, widgetParamExt);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitWindowMode fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    // appWindow is system-api-only and never crosses IPC; reject non-system callers here.
    if (widgetParam.appWindow.has_value() && !UserAuthAniHelper::IsSystemApiCaller()) {
        IAM_LOGE("appWindow used by non-system caller");
        return UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED;
    }

    if (widgetParam.uiContext.has_value()) {
        IAM_LOGI("widgetParam has uiContext");
        errorCode = InitContext(widgetParam, widgetParamExt, abilityContext);
        if (errorCode != UserAuthResultCode::SUCCESS) {
            IAM_LOGE("InitContext fail:%{public}d", errorCode);
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
    } else if (widgetParam.appWindow.has_value()) {
        IAM_LOGI("widgetParam has window");
        errorCode = InitWindow(widgetParam, widgetParamExt, window);
        if (errorCode != UserAuthResultCode::SUCCESS) {
            IAM_LOGE("InitWindow fail:%{public}d", errorCode);
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitTitle(userAuth::WidgetParam const &widgetParam,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt)
{
    IAM_LOGI("InitTitle start.");
    std::string title = widgetParam.title.c_str();
    if (title == "" || UserAuthHelper::GetUtf8CharCount(title) > TITLE_MAX) {
        IAM_LOGE("title is invalid. size: %{public}zu", UserAuthHelper::GetUtf8CharCount(title));
        std::string msgStr = "Parameter error. The length of \"title\" connot exceed 500.";
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    widgetParamExt.title = title;
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitNavigationButtonText(userAuth::WidgetParam const &widgetParam,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt)
{
    IAM_LOGI("InitNavigationButtonText start.");
    if (widgetParam.navigationButtonText.has_value()) {
        std::string naviBtnTxt = widgetParam.navigationButtonText->c_str();
        if (naviBtnTxt == "" || UserAuthHelper::GetUtf8CharCount(naviBtnTxt) > WidgetType::BUTTON_MAX) {
            IAM_LOGE("navigation button text is invalid, size: %{public}zu",
                UserAuthHelper::GetUtf8CharCount(naviBtnTxt));
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        widgetParamExt.navigationButtonText = naviBtnTxt;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitWindowMode(userAuth::WidgetParam const &widgetParam,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt)
{
    IAM_LOGI("InitWindowMode start.");
    if (widgetParam.windowMode.has_value()) {
        switch (widgetParam.windowMode->get_key()) {
            case userAuth::WindowModeType::key_t::DIALOG_BOX:
                widgetParamExt.windowMode = WindowModeType::DIALOG_BOX;
                break;
            case userAuth::WindowModeType::key_t::FULLSCREEN:
                widgetParamExt.windowMode = WindowModeType::FULLSCREEN;
                break;
            default:
                IAM_LOGE("windowMode type not support.");
                return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        IAM_LOGI("widgetParam title:%{public}s, navBtnText:%{public}s, winMode:%{public}u",
            widgetParamExt.title.c_str(),
            widgetParamExt.navigationButtonText.c_str(),
            static_cast<uint32_t>(widgetParamExt.windowMode));
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitContext(userAuth::WidgetParam const &widgetParam,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt,
    std::shared_ptr<AbilityRuntime::Context> &abilityContext)
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
        widgetParamExt.hasContext = true;
        IAM_LOGI("widgetParam has valid uiContext");
    } else {
        // Default as modal system
        IAM_LOGI("widgetParam has invalid uiContext, not base on valid AbilityContext or UIExtensionContext.");
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::InitWindow(userAuth::WidgetParam const &widgetParam,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt, sptr<OHOS::Rosen::Window> &window)
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
    widgetParamExt.hasContext = true;
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

UserAuthResultCode UserAuthParamUtils::FillAuthResult(int32_t result, const Attributes &extraInfo,
    userAuth::UserAuthResult &userAuthResult)
{
    std::vector<uint8_t> token = {};
    int32_t authType = 0;
    EnrolledState enrolledState = {};
    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token)) {
        IAM_LOGE("ATTR_SIGNATURE is null");
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_AUTH_TYPE, authType)) {
        IAM_LOGE("ATTR_AUTH_TYPE is null");
    }
    if (!extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, enrolledState.credentialDigest)) {
        IAM_LOGE("ATTR_CREDENTIAL_DIGEST is null");
    }
    if (!extraInfo.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, enrolledState.credentialCount)) {
        IAM_LOGE("ATTR_CREDENTIAL_COUNT is null");
    }
    userAuthResult.result = UserAuthHelper::GetResultCodeV10(result);
    if (!token.empty()) {
        userAuthResult.token =
            taihe::optional<taihe::array<uint8_t>>(
                std::in_place_t{}, taihe::copy_data_t{}, token.data(), token.size());
    }
    if (UserAuthHelper::CheckUserAuthType(authType)) {
        userAuth::UserAuthType authTypeAni(userAuth::UserAuthType::key_t::PIN);
        if (!UserAuthAniHelper::ConvertUserAuthType(authType, authTypeAni)) {
            IAM_LOGE("Set authType error. authType: %{public}d", authType);
            return UserAuthResultCode::GENERAL_ERROR;
        }
        userAuthResult.authType = taihe::optional<userAuth::UserAuthType>::make(authTypeAni);
    }
    if (UserAuthResultCode(userAuthResult.result) == UserAuthResultCode::SUCCESS || !token.empty()) {
        userAuth::EnrolledState enrolledStateAni = {enrolledState.credentialDigest, enrolledState.credentialCount};
        userAuthResult.enrolledState = taihe::optional<userAuth::EnrolledState>::make(enrolledStateAni);
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthParamUtils::GetUserAuthResult(int32_t result, const Attributes &extraInfo,
    userAuth::UserAuthResult &userAuthResult)
{
    UserAuthResultCode errorCode = FillAuthResult(result, extraInfo, userAuthResult);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    int32_t int32Value = 0;
    if (extraInfo.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, int32Value)) {
        userAuthResult.remainingAuthAttempts = taihe::optional<int32_t>::make(int32Value);
    }
    if (extraInfo.GetInt32Value(Attributes::ATTR_FREEZING_TIME, int32Value)) {
        userAuthResult.lockoutDuration = taihe::optional<int32_t>::make(int32Value);
    }
    if (extraInfo.GetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, int32Value)) {
        userAuthResult.nextPhaseLockoutDuration = taihe::optional<int32_t>::make(int32Value);
    }
    uint64_t credentialId = 0;
    if (extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_ID, credentialId)) {
        std::vector<uint8_t> credentialIdVec(sizeof(credentialId), 0);
        for (size_t i = 0; i < credentialIdVec.size(); ++i) {
            credentialIdVec[i] = static_cast<uint8_t>((credentialId >> (i * BITS_PER_BYTE)) & 0xFF);
        }
        userAuthResult.credentialId = taihe::optional<taihe::array<uint8_t>>(
            std::in_place_t{}, taihe::copy_data_t{}, credentialIdVec.data(), credentialIdVec.size());
    }
    if (extraInfo.GetInt32Value(Attributes::ATTR_USER_ID, int32Value)) {
        userAuthResult.userId = taihe::optional<int32_t>::make(int32Value);
    }
    int64_t int64Value = 0;
    if (extraInfo.GetInt64Value(Attributes::ATTR_PIN_EXPIRED_INFO, int64Value)) {
        userAuthResult.pinValidityPeriod = taihe::optional<int64_t>::make(int64Value);
    }
    return UserAuthResultCode::SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

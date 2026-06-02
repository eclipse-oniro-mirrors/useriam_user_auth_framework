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

#include "user_auth_instance_v10.h"

#include <string>
#include <cinttypes>
#include <algorithm>

#include "taihe/runtime.hpp"
#include "securec.h"
#include "ani_base_context.h"
#include "ui_content.h"
#include "ui_extension_context.h"
#include "ui_holder_extension_context.h"

#include "iam_logger.h"
#include "user_auth_helper.h"
#include "user_auth_ani_helper.h"
#include "user_auth_common_defines.h"
#include "user_auth_client_impl.h"
#include "user_auth_api_event_reporter.h"

#define LOG_TAG "USER_AUTH_ANI"

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

UserAuthInstanceV10::UserAuthInstanceV10() : callback_(Common::MakeShared<UserAuthCallbackV10>())
{
    if (callback_ == nullptr) {
        IAM_LOGE("get null callback");
    }
    authParam_.authTrustLevel = AuthTrustLevel::ATL1;
    authParam_.userId = INVALID_USER_ID;
    authParam_.isUserIdSpecified = false;
    authParam_.skipLockedBiometricAuth = false;
    authParam_.reuseUnlockResult.isReuse = false;
    widgetParam_.navigationButtonText = "";
    widgetParam_.title = "";
    widgetParam_.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
}

UserAuthResultCode UserAuthInstanceV10::Init(
    userAuth::AuthParam const &authParam, userAuth::WidgetParam const &widgetParam)
{
    IAM_LOGI("Init start");
    UserAuthResultCode errCode = InitAuthParam(authParam);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("AuthParamInner type error, errorCode: %{public}d", errCode);
        return errCode;
    }

    errCode = InitWidgetParam(widgetParam);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("WidgetParam type error, errorCode: %{public}d", errCode);
        return errCode;
    }
    IAM_LOGI("Init SUCCESS");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitAuthParam(userAuth::AuthParam const &authParam)
{
    IAM_LOGI("InitAuthParam start");
    std::vector<uint8_t> challenge(authParam.challenge.begin(), authParam.challenge.end());
    authParam_.challenge = challenge;

    UserAuthResultCode errorCode = InitAuthType(authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthType fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitAuthTrustLevel(authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthTrustLevel fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitReuseUnlockResult(authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthTrustLevel fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitUserId(authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitUserId fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitSkipLockedBiometricAuth(authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitSkipLockedBiometricAuth fail:%{public}d", errorCode);
        return errorCode;
    }

    errorCode = InitCredentialIdList(authParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitCredentialIdList fail:%{public}d", errorCode);
        return errorCode;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitAuthType(userAuth::AuthParam const &authParam)
{
    IAM_LOGI("InitAuthType start.");
    for (const auto &type : authParam.authType) {
        if (!UserAuthHelper::CheckUserAuthType(type)) {
            IAM_LOGE("authType is illegal, %{public}d", type.get_value());
            return UserAuthResultCode::TYPE_NOT_SUPPORT;
        }
        authParam_.authTypes.push_back(static_cast<AuthType>(static_cast<std::int32_t>(type.get_value())));
    }
    IAM_LOGI("authType size:%{public}zu", authParam_.authTypes.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitAuthTrustLevel(userAuth::AuthParam const &authParam)
{
    IAM_LOGI("InitAuthTrustLevel start.");
    auto authTrustLevel = authParam.authTrustLevel;
    if (!UserAuthHelper::CheckAuthTrustLevel(authTrustLevel)) {
        IAM_LOGE("AuthTrustLevel fail:%{public}u", authTrustLevel.get_value());
        return UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT;
    }
    authParam_.authTrustLevel = AuthTrustLevel(static_cast<int32_t>(authTrustLevel));
    IAM_LOGI("authTrustLevel:%{public}u", authParam_.authTrustLevel);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitReuseUnlockResult(userAuth::AuthParam const &authParam)
{
    IAM_LOGI("InitReuseUnlockResult start.");
    if (authParam.reuseUnlockResult.has_value()) {
        authParam_.reuseUnlockResult.isReuse = true;
        authParam_.reuseUnlockResult.reuseMode =
            ReuseMode(static_cast<int32_t>(authParam.reuseUnlockResult->reuseMode.get_value()));
        authParam_.reuseUnlockResult.reuseDuration = authParam.reuseUnlockResult->reuseDuration;
        if (!UserAuthHelper::CheckReuseUnlockResult(authParam_.reuseUnlockResult)) {
            IAM_LOGE("ReuseUnlockResult fail");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        authParam_.reuseUnlockResult.reuseDuration = authParam.reuseUnlockResult->reuseDuration;
        IAM_LOGI("reuseMode: %{public}u, reuseDuration: %{public}" PRIu64,
                 authParam_.reuseUnlockResult.reuseMode,
                 authParam_.reuseUnlockResult.reuseDuration);
    } else {
        IAM_LOGI("propertyName: %{public}s not exists.", AUTH_PARAM_REUSEUNLOCKRESULT.c_str());
        authParam_.reuseUnlockResult.isReuse = false;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitUserId(userAuth::AuthParam const &authParam)
{
    IAM_LOGI("InitUserId start.");
    if (authParam.userId.has_value()) {
        authParam_.userId = authParam.userId.value();
        authParam_.isUserIdSpecified = true;
        if (authParam_.userId < 0) {
            IAM_LOGE("userId error.");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        IAM_LOGI("InitUserId userId: %{public}d", authParam_.userId);
    } else {
        IAM_LOGI("propertyName: %{public}s not exists.", AUTH_PARAM_USER_ID.c_str());
        authParam_.isUserIdSpecified = false;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitSkipLockedBiometricAuth(userAuth::AuthParam const &authParam)
{
    IAM_LOGI("InitSkipLockedBiometricAuth start.");
    if (authParam.skipLockedBiometricAuth.has_value()) {
        authParam_.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth.value();
        IAM_LOGI("InitSkipLockedBiometricAuth value: %{public}d", authParam_.skipLockedBiometricAuth);
    } else {
        IAM_LOGI("propertyName: %{public}s not exists.", AUTH_PARAM_SKIP_LOCKED_BIOMETRIC_AUTH.c_str());
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitCredentialIdList(userAuth::AuthParam const &authParam)
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
    authParam_.credentialIdList.clear();
    authParam_.credentialIdList.reserve(credentialIdList.size());
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
        authParam_.credentialIdList.push_back(dest);
    }
    IAM_LOGI("InitCredentialIdList.size(): %{public}zu", authParam_.credentialIdList.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitWidgetParam(userAuth::WidgetParam const &widgetParam)
{
    IAM_LOGI("InitWidgetParam start.");
    UserAuthResultCode errorCode = InitTitle(widgetParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitTitle fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    errorCode = InitNavigationButtonText(widgetParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitNavigationButtonText fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    errorCode = InitWindowMode(widgetParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitWindowMode fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    errorCode = InitContext(widgetParam);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitContext fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitTitle(userAuth::WidgetParam const &widgetParam)
{
    IAM_LOGI("InitTitle start.");
    std::string title = widgetParam.title.c_str();
    if (title == "" || UserAuthHelper::GetUtf8CharCount(title) > TITLE_MAX) {
        IAM_LOGE("title is invalid. size: %{public}zu", UserAuthHelper::GetUtf8CharCount(title));
        std::string msgStr = "Parameter error. The length of \"title\" connot exceed 500.";
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    widgetParam_.title = title;
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitNavigationButtonText(userAuth::WidgetParam const &widgetParam)
{
    IAM_LOGI("InitNavigationButtonText start.");
    if (widgetParam.navigationButtonText.has_value()) {
        std::string naviBtnTxt = widgetParam.navigationButtonText->c_str();
        if (naviBtnTxt == "" || UserAuthHelper::GetUtf8CharCount(naviBtnTxt) > WidgetType::BUTTON_MAX) {
            IAM_LOGE("navigation button text is invalid, size: %{public}zu",
                UserAuthHelper::GetUtf8CharCount(naviBtnTxt));
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        widgetParam_.navigationButtonText = naviBtnTxt;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitWindowMode(userAuth::WidgetParam const &widgetParam)
{
    IAM_LOGI("InitWindowMode start.");
    if (widgetParam.windowMode.has_value()) {
        switch (widgetParam.windowMode->get_key()) {
            case userAuth::WindowModeType::key_t::DIALOG_BOX:
                widgetParam_.windowMode = WindowModeType::DIALOG_BOX;
                break;
            case userAuth::WindowModeType::key_t::FULLSCREEN:
                widgetParam_.windowMode = WindowModeType::FULLSCREEN;
                break;
            default:
                IAM_LOGE("windowMode type not support.");
                return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        IAM_LOGI("widgetParam title:%{public}s, navBtnText:%{public}s, winMode:%{public}u",
            widgetParam_.title.c_str(),
            widgetParam_.navigationButtonText.c_str(),
            static_cast<uint32_t>(widgetParam_.windowMode));
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitContext(userAuth::WidgetParam const &widgetParam)
{
    IAM_LOGI("InitContext start.");
    if (widgetParam.uiContext.has_value()) {
        IAM_LOGI("widgetParam has uiContext");
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
            context_ = context;
            widgetParam_.hasContext = true;
            IAM_LOGI("widgetParam has valid uiContext");
        } else {
            // Default as modal system
            IAM_LOGI("widgetParam has invalid uiContext, not base on valid AbilityContext or UIExtensionContext.");
        }
    }
    return UserAuthResultCode::SUCCESS;
}

bool UserAuthInstanceV10::CheckUIContext(const std::shared_ptr<AbilityRuntime::Context> context)
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

UserAuthResultCode UserAuthInstanceV10::OnResult(userAuth::IAuthCallback const &callback)
{
    IAM_LOGI("UserAuthInstanceV10 OnResult.");
    if (callback_ == nullptr) {
        IAM_LOGE("userAuthInstance OnResult callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (callback_->HasResultCallback()) {
        IAM_LOGE("callback has been registered");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    IAM_LOGI("getAuthInstance OnResult SetResultCallback");
    callback_->SetResultCallback(callback);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::OffResult(taihe::optional_view<userAuth::IAuthCallback> callback)
{
    IAM_LOGI("UserAuthInstanceV10 OffResult.");
    if (callback_ == nullptr) {
        IAM_LOGE("userAuthInstance OffResult callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }

    if (!callback_->HasResultCallback()) {
        IAM_LOGE("no callback registerred yet");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    callback_->ClearResultCallback();
    IAM_LOGI("UserAuthResultCode OffResult clear result callback");
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::Start()
{
    IAM_LOGI("UserAuthInstanceV10 start.");
    UserAuthApiEventReporter reporter("UserAuthInstance::start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        reporter.ReportFailed(UserAuthResultCode::GENERAL_ERROR);
        return UserAuthResultCode::GENERAL_ERROR;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    if (isAuthStarted_) {
        IAM_LOGE("auth already started");
        reporter.ReportFailed(UserAuthResultCode::GENERAL_ERROR);
        return UserAuthResultCode::GENERAL_ERROR;
    }

    modalCallback_ = Common::MakeShared<UserAuthModalCallback>(context_);
    contextId_ = UserAuthNapiClientImpl::Instance().BeginWidgetAuth(
        API_VERSION_10, authParam_, widgetParam_, callback_, modalCallback_);
    isAuthStarted_ = true;
    reporter.ReportSuccess();
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::Cancel()
{
    IAM_LOGI("UserAuthInstanceV10 cancel.");
    UserAuthApiEventReporter reporter("UserAuthInstance::cancel");
    std::lock_guard<std::mutex> guard(mutex_);
    if (!isAuthStarted_) {
        IAM_LOGE("auth not started");
        reporter.ReportFailed(UserAuthResultCode::GENERAL_ERROR);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    int32_t result = UserAuthClient::GetInstance().CancelAuthentication(contextId_);
    if (result != ResultCode::SUCCESS) {
        IAM_LOGE("CancelAuthentication fail:%{public}d", result);
        UserAuthResultCode resultCode = UserAuthResultCode(UserAuthHelper::GetResultCodeV10(result));
        reporter.ReportFailed(resultCode);
        return resultCode;
    }
    isAuthStarted_ = false;
    reporter.ReportSuccess();
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::onAuthTip(taihe::callback_view<void(userAuth::AuthTipInfo const &)> callback)
{
    IAM_LOGI("UserAuthInstanceV10 onAuthTip.");
    if (callback_ == nullptr) {
        IAM_LOGE("userAuthInstance onAuthTip callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (callback_->HasTipCallback()) {
        IAM_LOGE("callback has been registered");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    IAM_LOGI("getAuthInstance onAuthTip SetTipCallback");
    callback_->SetTipCallback(
        taihe::optional<::taihe::callback<void(userAuth::AuthTipInfo const &)>>{std::in_place_t{}, callback});
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::offAuthTip(
    taihe::optional_view<taihe::callback<void(userAuth::AuthTipInfo const &)>> callback)
{
    IAM_LOGI("UserAuthInstanceV10 offAuthTip.");
    if (callback_ == nullptr) {
        IAM_LOGE("userAuthInstance offAuthTip callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }

    if (!callback_->HasTipCallback()) {
        IAM_LOGE("no callback registerred yet");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    callback_->ClearTipCallback();
    IAM_LOGI("UserAuthResultCode offAuthTip clear tip callback");
    return UserAuthResultCode::SUCCESS;
}
}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS
 
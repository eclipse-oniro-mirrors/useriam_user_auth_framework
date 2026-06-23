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
#include "user_auth_param_utils.h"

#define LOG_TAG "USER_AUTH_ANI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_INSTANCE_V10_ANI

namespace userAuth = ohos::userIAM::userAuth::userAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
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
    UserAuthResultCode errCode = UserAuthParamUtils::InitAuthParam(authParam, authParam_);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("AuthParamInner type error, errorCode: %{public}d", errCode);
        return errCode;
    }

    errCode = UserAuthParamUtils::InitWidgetParam(widgetParam, widgetParam_, context_);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("WidgetParam type error, errorCode: %{public}d", errCode);
        return errCode;
    }
    IAM_LOGI("Init SUCCESS");
    return UserAuthResultCode::SUCCESS;
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
 

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

#include "ohos.userIAM.userAuth.userAuth.proj.hpp"
#include "ohos.userIAM.userAuth.userAuth.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "iam_ptr.h"
#include "iam_logger.h"
#include "auth_common.h"
#include "user_auth_helper.h"
#include "user_auth_ani_helper.h"
#include "user_auth_client_impl.h"
#include "user_auth_common_defines.h"
#include "user_auth_instance_v10.h"
#include "user_auth_widget_mgr_v10.h"
#include "user_auth_api_event_reporter.h"

#define LOG_TAG "USER_AUTH_ANI"

namespace UserAuth = OHOS::UserIam::UserAuth;
using namespace taihe;
using namespace ohos::userIAM::userAuth::userAuth;
using namespace OHOS::UserIam::Common;

namespace {

class UserAuthInstanceImpl {
public:
    UserAuthInstanceImpl(AuthParam const &authParam, WidgetParam const &widgetParam)
    {
        userAuthInstanceV10_ = MakeShared<UserAuth::UserAuthInstanceV10>();
        init(authParam, widgetParam);
    }

    void init(AuthParam const &authParam, WidgetParam const &widgetParam)
    {
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode initResult = userAuthInstanceV10_->Init(authParam, widgetParam);
        if (initResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ init fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(initResult);
            return;
        }
    }

    void on(string_view type, IAuthCallback const &callback)
    {
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode onResult = userAuthInstanceV10_->On(type.c_str(), callback);
        if (onResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ on fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(onResult);
            return;
        }
    }

    void off(string_view type, optional_view<IAuthCallback> callback)
    {
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode offResult = userAuthInstanceV10_->Off(type.c_str(), callback);
        if (offResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ off fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(offResult);
            return;
        }
    }

    void start()
    {
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode startResult = userAuthInstanceV10_->Start();
        if (startResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ start fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(startResult);
            return;
        }
    }

    void cancel()
    {
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode canelResult = userAuthInstanceV10_->Cancel();
        if (canelResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ cancel fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(canelResult);
            return;
        }
    }

private:
    std::shared_ptr<UserAuth::UserAuthInstanceV10> userAuthInstanceV10_ = nullptr;
};

class UserAuthWidgetMgrImpl {
public:
    explicit UserAuthWidgetMgrImpl(int32_t version)
    {
        userAuthWidgetMgr_ = MakeShared<UserAuth::UserAuthWidgetMgr>();
        init(version);
    }

    void init(int32_t version)
    {
        if (userAuthWidgetMgr_ == nullptr) {
            IAM_LOGE("userAuthWidgetMgr_ is null after MakeShared");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode initResult = userAuthWidgetMgr_->Init(version);
        if (initResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthWidgetMgr_ init fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(initResult);
            return;
        }
    }

    void on(string_view type, IAuthWidgetCallback const &callback)
    {
        if (userAuthWidgetMgr_ == nullptr) {
            IAM_LOGE("userAuthWidgetMgr_ is null after MakeShared");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode onResult = userAuthWidgetMgr_->On(type.c_str(), callback);
        if (onResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthWidgetMgr_ on fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(onResult);
            return;
        }
    }

    void off(string_view type, optional_view<IAuthWidgetCallback> callback)
    {
        if (userAuthWidgetMgr_ == nullptr) {
            IAM_LOGE("userAuthWidgetMgr_ is null after MakeShared");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode offResult = userAuthWidgetMgr_->Off(type.c_str(), callback);
        if (offResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthWidgetMgr_ off fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(offResult);
            return;
        }
    }

private:
    std::shared_ptr<UserAuth::UserAuthWidgetMgr> userAuthWidgetMgr_ = nullptr;
};

void GetAvailableStatus(UserAuthType authType, AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("GetAvailableStatus begin");
    UserAuth::UserAuthApiEventReporter reporter("getAvailableStatus");
    if (!UserAuth::UserAuthHelper::CheckUserAuthType(authType)) {
        IAM_LOGE("authType check fail:%{public}d", authType.get_value());
        reporter.ReportFailed(UserAuth::UserAuthResultCode::TYPE_NOT_SUPPORT);
        UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::TYPE_NOT_SUPPORT);
        return;
    }
    if (!UserAuth::UserAuthHelper::CheckAuthTrustLevel(authTrustLevel)) {
        IAM_LOGE("authTrustLevel check fail:%{public}d", authTrustLevel.get_value());
        reporter.ReportFailed(UserAuth::UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT);
        UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT);
        return;
    }
    int32_t status = UserAuth::UserAuthClientImpl::Instance().GetNorthAvailableStatus(UserAuth::API_VERSION_9,
        UserAuth::AuthType(authType.get_value()), UserAuth::AuthTrustLevel(authTrustLevel.get_value()));
    IAM_LOGI("result = %{public}d", status);
    if (status == static_cast<int32_t>(UserAuth::UserAuthResultCode::PIN_EXPIRED)) {
        reporter.ReportFailed(UserAuth::UserAuthResultCode::PIN_EXPIRED);
        UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::PIN_EXPIRED);
        return;
    }
    reporter.ReportSuccess();
}

EnrolledState GetEnrolledState(UserAuthType authType)
{
    IAM_LOGI("GetEnrolledState begin");
    UserAuth::UserAuthApiEventReporter reporter("getEnrolledState");
    if (!UserAuth::UserAuthHelper::CheckUserAuthType(authType)) {
        IAM_LOGE("authType check fail:%{public}d", authType.get_value());
        reporter.ReportFailed(UserAuth::UserAuthResultCode::TYPE_NOT_SUPPORT);
        UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::TYPE_NOT_SUPPORT);
        return {};
    }
    UserAuth::EnrolledState enrolledState = {};
    int32_t code = UserAuth::UserAuthClientImpl::Instance().GetEnrolledState(
        UserAuth::API_VERSION_12, UserAuth::AuthType(authType.get_value()), enrolledState);
    if (code != static_cast<int32_t>(UserAuth::AuthenticationResult::SUCCESS)) {
        IAM_LOGE("failed to get enrolled state %{public}d", code);
        UserAuth::UserAuthResultCode resultCode = UserAuth::UserAuthResultCode(
            UserAuth::UserAuthHelper::GetResultCodeV10(code));
        reporter.ReportFailed(resultCode);
        UserAuth::UserAuthAniHelper::ThrowBusinessError(resultCode);
        return {};
    }
    EnrolledState result{enrolledState.credentialDigest, enrolledState.credentialCount};
    reporter.ReportSuccess();
    return result;
}

UserAuthInstance GetUserAuthInstance(AuthParam const &authParam, WidgetParam const &widgetParam)
{
    IAM_LOGI("GetUserAuthInstance begin");
    UserAuth::UserAuthApiEventReporter reporter("getUserAuthInstance");
    auto userAuthInstance = make_holder<UserAuthInstanceImpl, UserAuthInstance>(authParam, widgetParam);
    reporter.ReportSuccess();
    return userAuthInstance;
}

void SendNotice(NoticeType noticeType, string_view eventData)
{
    IAM_LOGI("SendNotice begin");
    UserAuth::NoticeType type = UserAuth::NoticeType(noticeType.get_value());
    IAM_LOGI("recv SendNotice noticeType:%{public}d eventData:%{public}s", type, eventData.c_str());
    if (!UserAuth::UserAuthAniHelper::VerifyNoticeParam(eventData.c_str())) {
        IAM_LOGE("Invalid notice parameter");
        UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM);
        return;
    }

    int32_t result = UserAuth::UserAuthClientImpl::Instance().Notice(type, eventData.c_str());
    UserAuth::UserAuthResultCode errCode = UserAuth::UserAuthResultCode::SUCCESS;
    if (result != static_cast<int32_t>(UserAuth::ResultCode::SUCCESS)) {
        errCode = UserAuth::UserAuthResultCode(UserAuth::UserAuthHelper::GetResultCodeV10(result));
        IAM_LOGE("SendNotice fail. result: %{public}d, errCode: %{public}d", result, errCode);
        UserAuth::UserAuthAniHelper::ThrowBusinessError(errCode);
        return;
    }
    IAM_LOGI("end SendNotice");
}

UserAuth::WidgetAuthParam ConvertAuthParamToWidgetAuthParam(AuthParam const &authParam)
{
    UserAuth::WidgetAuthParam widgetAuthParam = {};
    widgetAuthParam.challenge = std::vector<uint8_t>(authParam.challenge.begin(), authParam.challenge.end());
    widgetAuthParam.authTrustLevel = UserAuth::AuthTrustLevel(authParam.authTrustLevel.get_value());

    for (const auto &type : authParam.authType) {
        widgetAuthParam.authTypes.push_back(static_cast<UserAuth::AuthType>(type.get_value()));
    }

    if (authParam.userId.has_value()) {
        widgetAuthParam.userId = static_cast<int32_t>(authParam.userId.value());
    } else {
        widgetAuthParam.userId = UserAuth::INVALID_USER_ID;
    }

    if (authParam.reuseUnlockResult.has_value()) {
        widgetAuthParam.reuseUnlockResult.isReuse = true;
        widgetAuthParam.reuseUnlockResult.reuseMode = static_cast<UserAuth::ReuseMode>(
            authParam.reuseUnlockResult->reuseMode.get_value());
        widgetAuthParam.reuseUnlockResult.reuseDuration =
            static_cast<uint64_t>(authParam.reuseUnlockResult->reuseDuration);
    } else {
        widgetAuthParam.reuseUnlockResult.isReuse = false;
    }

    return widgetAuthParam;
}

array<uint8_t> QueryReusableAuthResult(AuthParam const &authParam)
{
    IAM_LOGI("QueryReusableAuthResult begin");

    UserAuth::WidgetAuthParam widgetAuthParam = ConvertAuthParamToWidgetAuthParam(authParam);

    std::vector<uint8_t> token;
    int32_t code = UserAuth::UserAuthClientImpl::Instance().QueryReusableAuthResult(widgetAuthParam, token);
    if (code != UserAuth::SUCCESS) {
        IAM_LOGE("failed to query reuse result %{public}d", code);
        UserAuth::UserAuthResultCode resultCode = UserAuth::UserAuthResultCode(
            UserAuth::UserAuthHelper::GetResultCodeV10(code));
        UserAuth::UserAuthAniHelper::ThrowBusinessError(resultCode);
        return {};
    }

    return taihe::array<uint8_t>(taihe::copy_data_t{}, token.data(), token.size());
}

UserAuthWidgetMgr GetUserAuthWidgetMgr(int32_t version)
{
    IAM_LOGI("GetUserAuthWidgetMgr begin");
    auto userAuthWidgetMgr = make_holder<UserAuthWidgetMgrImpl, UserAuthWidgetMgr>(version);
    return userAuthWidgetMgr;
}
}  // namespace

TH_EXPORT_CPP_API_GetAvailableStatus(GetAvailableStatus);
TH_EXPORT_CPP_API_GetEnrolledState(GetEnrolledState);
TH_EXPORT_CPP_API_GetUserAuthInstance(GetUserAuthInstance);
TH_EXPORT_CPP_API_SendNotice(SendNotice);
TH_EXPORT_CPP_API_QueryReusableAuthResult(QueryReusableAuthResult);
TH_EXPORT_CPP_API_GetUserAuthWidgetMgr(GetUserAuthWidgetMgr);

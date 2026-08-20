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

#include "ohos.userIAM.userAuth.userAuth.impl.hpp"

#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

#include "ohos.userIAM.userAuth.userAuth.proj.hpp"
#include "taihe/runtime.hpp"

#include "attributes.h"
#include "iam_check.h"
#include "iam_ptr.h"
#include "iam_logger.h"
#include "auth_common.h"
#include "auth_lock_state_helper.h"
#include "user_auth_helper.h"
#include "user_auth_ani_helper.h"
#include "user_auth_client_impl.h"
#include "user_auth_common_defines.h"
#include "user_auth_instance_v10.h"
#include "user_auth_widget_mgr_v10.h"
#include "user_auth_api_event_reporter.h"
#include "user_auth_client_callback.h"
#include "user_auth_remote_auth_callback.h"

#define LOG_TAG "USER_AUTH_ANI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_ANI_IMPL

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
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode initResult = userAuthInstanceV10_->Init(authParam, widgetParam);
        if (initResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ init fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(initResult);
            userAuthInstanceV10_ = nullptr;
            return;
        }
    }

    bool IsValid()
    {
        return userAuthInstanceV10_ != nullptr;
    }

    void onResult(IAuthCallback const &callback)
    {
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode onResult = userAuthInstanceV10_->OnResult(callback);
        if (onResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ onResult fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(onResult);
            return;
        }
    }

    void offResult(optional_view<IAuthCallback> callback)
    {
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode offResult = userAuthInstanceV10_->OffResult(callback);
        if (offResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ offResult fail");
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
        UserAuth::UserAuthResultCode cancelResult = userAuthInstanceV10_->Cancel();
        if (cancelResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ cancel fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(cancelResult);
            return;
        }
    }

    void onAuthTip(callback_view<void(AuthTipInfo const&)> callback)
    {
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode onResult = userAuthInstanceV10_->onAuthTip(callback);
        if (onResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ onAuthTip fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(onResult);
            return;
        }
    }

    void offAuthTip(optional_view<callback<void(AuthTipInfo const&)>> callback)
    {
        if (userAuthInstanceV10_ == nullptr) {
            IAM_LOGE("userAuthInstanceV10_ is null");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode offResult = userAuthInstanceV10_->offAuthTip(callback);
        if (offResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthInstanceV10_ offAuthTip fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(offResult);
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

    void onCommand(IAuthWidgetCallback const &callback)
    {
        if (userAuthWidgetMgr_ == nullptr) {
            IAM_LOGE("userAuthWidgetMgr_ is null after MakeShared");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode onResult = userAuthWidgetMgr_->OnCommand(callback);
        if (onResult != UserAuth::UserAuthResultCode::SUCCESS) {
            IAM_LOGE("userAuthWidgetMgr_ on fail");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(onResult);
            return;
        }
    }

    void offCommand(optional_view<IAuthWidgetCallback> callback)
    {
        if (userAuthWidgetMgr_ == nullptr) {
            IAM_LOGE("userAuthWidgetMgr_ is null after MakeShared");
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        UserAuth::UserAuthResultCode offResult = userAuthWidgetMgr_->OffCommand(callback);
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
    if (!userAuthInstance->IsValid()) {
        reporter.ReportFailed(UserAuth::UserAuthResultCode::GENERAL_ERROR);
    } else {
        reporter.ReportSuccess();
    }
    return userAuthInstance;
}

void SendNotice(NoticeType noticeType, string_view eventData)
{
    IAM_LOGI("SendNotice begin");
    UserAuth::NoticeType type = UserAuth::NoticeType(noticeType.get_value());
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

UserAuth::UserAuthResultCode GetAuthLockStateSyncInner(UserAuthType authType, userAuth::AuthLockState &authLockState)
{
    IAM_LOGI("begin");
    const int32_t maxWaitTime = 10000;
    if (!UserAuth::UserAuthHelper::CheckUserAuthType(authType)) {
        IAM_LOGE("authType check failed:%{public}d", authType.get_value());
        return UserAuth::UserAuthResultCode::TYPE_NOT_SUPPORT;
    }

    std::shared_ptr<UserAuth::GetAuthLockStateCallback> callback =
        MakeShared<UserAuth::GetAuthLockStateCallback>();
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, UserAuth::UserAuthResultCode::GENERAL_ERROR);
    UserAuth::UserAuthClientImpl::Instance().GetAuthLockState(UserAuth::AuthType(authType.get_value()), callback);
    auto future = callback->GetFuture();
    auto result = future.wait_for(std::chrono::milliseconds(maxWaitTime));
    if (result == std::future_status::timeout) {
        IAM_LOGE("GetAuthLockState timeout");
        return UserAuth::UserAuthResultCode::GENERAL_ERROR;
    }

    UserAuth::GetAuthLockStateResult getAuthLockStateResult = future.get();
    if (getAuthLockStateResult.resultCode != static_cast<int32_t>(UserAuth::ResultCode::SUCCESS)) {
        IAM_LOGE("GetAuthLockState failed, resultCode:%{public}d", getAuthLockStateResult.resultCode);
        return UserAuth::UserAuthResultCode(UserAuth::UserAuthHelper::
            GetResultCodeV21(getAuthLockStateResult.resultCode));
    }
    UserAuth::Attributes attr(getAuthLockStateResult.authLockState);
    bool getAttrRes = attr.GetInt32Value(UserAuth::Attributes::ATTR_REMAIN_ATTEMPTS,
        authLockState.remainingAuthAttempts);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAttrRes, UserAuth::UserAuthResultCode::GENERAL_ERROR);
    getAttrRes = attr.GetInt32Value(UserAuth::Attributes::ATTR_LOCKOUT_DURATION,
        authLockState.lockoutDuration);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAttrRes, UserAuth::UserAuthResultCode::GENERAL_ERROR);
    authLockState.isLocked = authLockState.lockoutDuration > 0;
    IAM_LOGD("success");
    return UserAuth::UserAuthResultCode::SUCCESS;
}

userAuth::AuthLockState getAuthLockStateSync(UserAuthType authType)
{
    IAM_LOGD("begin");
    UserAuth::UserAuthApiEventReporter reporter("GetAuthLockStateSync");
    userAuth::AuthLockState authLockState = {};
    auto res = GetAuthLockStateSyncInner(authType, authLockState);
    if (res != UserAuth::UserAuthResultCode::SUCCESS) {
        IAM_LOGE("failed to get auth lock state inner %{public}d", res);
        reporter.ReportFailed(res);
        UserAuth::UserAuthAniHelper::ThrowBusinessError(res);
        return authLockState;
    }

    IAM_LOGD("success");
    reporter.ReportSuccess();
    return authLockState;
}

void RegisterRemoteAuthCallback(::ohos::userIAM::userAuth::userAuth::IRemoteAuthCallback const &callback)
{
    IAM_LOGD("begin");
    UserAuth::UserAuthApiEventReporter reporter("RegisterRemoteAuthCallback");
    auto remoteAuthCallback = MakeShared<UserAuth::RemoteAuthCallback>(callback);
    IF_FALSE_LOGE_AND_RETURN(remoteAuthCallback != nullptr);
    int32_t result =  UserAuth::UserAuthClientImpl::Instance().RegisterRemoteAuthCallback(remoteAuthCallback);
    if (result != UserAuth::SUCCESS) {
        IAM_LOGE("failed to register remote auth callback %{public}d", result);
        UserAuth::UserAuthResultCode resultCode = UserAuth::UserAuthResultCode(
            UserAuth::UserAuthHelper::GetResultCodeV10(result));
        reporter.ReportFailed(resultCode);
        UserAuth::UserAuthAniHelper::ThrowBusinessError(resultCode);
        return;
    }

    IAM_LOGD("success");
    reporter.ReportSuccess();
}

void UnregisterRemoteAuthCallback()
{
    IAM_LOGD("begin");
    UserAuth::UserAuthApiEventReporter reporter("UnregisterRemoteAuthCallback");
    int32_t result = UserAuth::UserAuthClientImpl::Instance().UnregisterRemoteAuthCallback();
    if (result != UserAuth::SUCCESS) {
        IAM_LOGE("failed to unregister remote auth callback %{public}d", result);
        UserAuth::UserAuthResultCode resultCode = UserAuth::UserAuthResultCode(
            UserAuth::UserAuthHelper::GetResultCodeV10(result));
        reporter.ReportFailed(resultCode);
        UserAuth::UserAuthAniHelper::ThrowBusinessError(resultCode);
        return;
    }
    IAM_LOGD("success");
    reporter.ReportSuccess();
}

UserRecognitionStatus ConvertUserRecognitionStatus(int32_t status)
{
    if (status == static_cast<int32_t>(UserAuth::UserRecognitionStatus::MATCH)) {
        return UserRecognitionStatus(UserRecognitionStatus::key_t::MATCH);
    }
    if (status == static_cast<int32_t>(UserAuth::UserRecognitionStatus::MISMATCH)) {
        return UserRecognitionStatus(UserRecognitionStatus::key_t::MISMATCH);
    }
    return UserRecognitionStatus(UserRecognitionStatus::key_t::UNCERTAIN);
}

// The wire value (10000-40000) must map to the generated enum's named key; key_t is a dense
// index enum, so casting the wire value into key_t produces an invalid enum item.
taihe::optional<AuthTrustLevel> ConvertAuthTrustLevel(int32_t authTrustLevel)
{
    switch (authTrustLevel) {
        case UserAuth::ATL1:
            return taihe::optional<AuthTrustLevel>::make(AuthTrustLevel(AuthTrustLevel::key_t::ATL1));
        case UserAuth::ATL2:
            return taihe::optional<AuthTrustLevel>::make(AuthTrustLevel(AuthTrustLevel::key_t::ATL2));
        case UserAuth::ATL3:
            return taihe::optional<AuthTrustLevel>::make(AuthTrustLevel(AuthTrustLevel::key_t::ATL3));
        case UserAuth::ATL4:
            return taihe::optional<AuthTrustLevel>::make(AuthTrustLevel(AuthTrustLevel::key_t::ATL4));
        default:
            IAM_LOGE("invalid authTrustLevel:%{public}d", authTrustLevel);
            return taihe::optional<AuthTrustLevel>();
    }
}

UserRecognitionResult FillAniRecognitionResult(const UserAuth::UserRecognitionResult &src)
{
    taihe::optional<AuthTrustLevel> authTrustLevel;
    if (src.authTrustLevel.has_value() && src.status == UserAuth::UserRecognitionStatus::MATCH) {
        authTrustLevel = ConvertAuthTrustLevel(static_cast<int32_t>(*src.authTrustLevel));
    }
    return UserRecognitionResult{
        ConvertUserRecognitionStatus(static_cast<int32_t>(src.status)),
        src.userId,
        taihe::string(src.userInfo),
        authTrustLevel,
    };
}

class UserRecognitionAniCallback : public UserAuth::UserRecognitionEventListener {
public:
    explicit UserRecognitionAniCallback(callback<void(UserRecognitionResult const&)> cb) : cb_(std::move(cb)) {}
    void OnUserRecognitionEvent(const UserAuth::UserRecognitionResult &result) override
    {
        if (cb_.is_error()) {
            IAM_LOGE("recognition ani callback is in error state, skip event");
            return;
        }
        taihe::env_guard guard;
        if (guard.get_env() == nullptr) {
            IAM_LOGE("attach ani env fail, drop user recognition event");
            return;
        }
        UserRecognitionResult ani = FillAniRecognitionResult(result);
        cb_(ani);
    }

private:
    callback<void(UserRecognitionResult const&)> cb_;
};

using RecognitionCb = callback<void(UserRecognitionResult const&)>;
using RecognitionListenerEntry = std::pair<optional<RecognitionCb>, std::shared_ptr<UserRecognitionAniCallback>>;

class UserRecognitionManagerImpl {
public:
    UserRecognitionManagerImpl() = default;
    ~UserRecognitionManagerImpl()
    {
        std::lock_guard<std::mutex> guard(listenersMutex_);
        for (const auto &entry : listeners_) {
            UserAuth::UserAuthClient::GetInstance().UnregisterUserRecognitionEventListener(entry.second);
        }
        listeners_.clear();
    }

    UserRecognitionResult getUserRecognitionResult()
    {
        UserAuth::UserAuthApiEventReporter reporter("GetUserRecognitionResult");
        UserAuth::UserRecognitionResult result = {};
        int32_t ret = UserAuth::UserAuthClient::GetInstance().GetUserRecognitionResult(result);
        if (ret != UserAuth::SUCCESS) {
            IAM_LOGE("get user recognition result fail, ret:%{public}d", ret);
            UserAuth::UserAuthResultCode resultCode =
                UserAuth::UserAuthResultCode(UserAuth::UserAuthHelper::GetResultCodeV10(ret));
            reporter.ReportFailed(resultCode);
            UserAuth::UserAuthAniHelper::ThrowBusinessError(resultCode);
            return FillAniRecognitionResult(result);
        }
        reporter.ReportSuccess();
        return FillAniRecognitionResult(result);
    }

    void onUserRecognitionChange(callback_view<void(UserRecognitionResult const&)> callback)
    {
        UserAuth::UserAuthApiEventReporter reporter("OnUserRecognitionChange");
        optional<RecognitionCb> eventCb{std::in_place_t{}, callback};
        auto aniCb = MakeShared<UserRecognitionAniCallback>(RecognitionCb(callback));
        if (aniCb == nullptr) {
            IAM_LOGE("create recognition ani callback fail");
            reporter.ReportFailed(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            UserAuth::UserAuthAniHelper::ThrowBusinessError(UserAuth::UserAuthResultCode::GENERAL_ERROR);
            return;
        }
        std::lock_guard<std::mutex> guard(listenersMutex_);
        auto it = std::find_if(listeners_.begin(), listeners_.end(),
            [&eventCb](const RecognitionListenerEntry &entry) { return entry.first == eventCb; });
        if (it != listeners_.end()) {
            IAM_LOGI("user recognition callback already registered, skip");
            reporter.ReportSuccess();
            return;
        }
        int32_t ret = UserAuth::UserAuthClient::GetInstance().RegisterUserRecognitionEventListener(aniCb);
        if (ret != UserAuth::SUCCESS) {
            IAM_LOGE("register user recognition listener fail, ret:%{public}d", ret);
            UserAuth::UserAuthResultCode resultCode =
                UserAuth::UserAuthResultCode(UserAuth::UserAuthHelper::GetResultCodeV10(ret));
            reporter.ReportFailed(resultCode);
            UserAuth::UserAuthAniHelper::ThrowBusinessError(resultCode);
            return;
        }
        listeners_.emplace_back(std::move(eventCb), aniCb);
        reporter.ReportSuccess();
    }

    void offUserRecognitionChange(optional_view<callback<void(UserRecognitionResult const&)>> callback)
    {
        UserAuth::UserAuthApiEventReporter reporter("OffUserRecognitionChange");
        std::lock_guard<std::mutex> guard(listenersMutex_);
        if (callback.has_value()) {
            auto it = std::find_if(listeners_.begin(), listeners_.end(),
                [&callback](const RecognitionListenerEntry &entry) { return entry.first == callback; });
            if (it != listeners_.end()) {
                UserAuth::UserAuthClient::GetInstance().UnregisterUserRecognitionEventListener(it->second);
                listeners_.erase(it);
            } else {
                IAM_LOGI("user recognition callback not found");
            }
        } else {
            for (const auto &entry : listeners_) {
                UserAuth::UserAuthClient::GetInstance().UnregisterUserRecognitionEventListener(entry.second);
            }
            listeners_.clear();
        }
        reporter.ReportSuccess();
    }

private:
    std::vector<RecognitionListenerEntry> listeners_;
    std::mutex listenersMutex_;
};

optional<UserRecognitionMgr> getUserRecognitionMgr()
{
    IAM_LOGI("getUserRecognitionMgr begin");
    UserAuth::UserAuthApiEventReporter reporter("GetUserRecognitionMgr");
    int32_t ret = UserAuth::UserAuthClient::GetInstance().CheckUserRecognitionCapability();
    if (ret == UserAuth::SUCCESS) {
        reporter.ReportSuccess();
        return optional<UserRecognitionMgr>(std::in_place,
            make_holder<UserRecognitionManagerImpl, UserRecognitionMgr>());
    }
    if (ret == UserAuth::DEVICE_CAPABILITY_NOT_SUPPORT) {
        IAM_LOGI("user recognition not supported, return null");
        reporter.ReportSuccess();
        return {};
    }
    UserAuth::UserAuthResultCode resultCode =
        UserAuth::UserAuthResultCode(UserAuth::UserAuthHelper::GetResultCodeV10(ret));
    IAM_LOGE("check capability fail, ret:%{public}d", ret);
    reporter.ReportFailed(resultCode);
    UserAuth::UserAuthAniHelper::ThrowBusinessError(resultCode);
    return {};
}
}  // namespace

TH_EXPORT_CPP_API_GetAvailableStatus(GetAvailableStatus);
TH_EXPORT_CPP_API_GetEnrolledState(GetEnrolledState);
TH_EXPORT_CPP_API_GetUserAuthInstance(GetUserAuthInstance);
TH_EXPORT_CPP_API_SendNotice(SendNotice);
TH_EXPORT_CPP_API_QueryReusableAuthResult(QueryReusableAuthResult);
TH_EXPORT_CPP_API_GetUserAuthWidgetMgr(GetUserAuthWidgetMgr);
TH_EXPORT_CPP_API_getAuthLockStateSync(getAuthLockStateSync);
TH_EXPORT_CPP_API_getAuthLockState(getAuthLockStateSync);
TH_EXPORT_CPP_API_RegisterRemoteAuthCallback(RegisterRemoteAuthCallback);
TH_EXPORT_CPP_API_UnregisterRemoteAuthCallback(UnregisterRemoteAuthCallback);
TH_EXPORT_CPP_API_getUserRecognitionMgr(getUserRecognitionMgr);

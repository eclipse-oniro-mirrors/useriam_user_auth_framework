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

#include "user_auth_callback_v10.h"

#include "taihe/runtime.hpp"

#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_auth_client_impl.h"
#include "user_auth_helper.h"
#include "user_auth_ani_helper.h"
#include "user_auth_param_utils.h"

#define LOG_TAG "USER_AUTH_ANI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_CALLBACK_V10_ANI

namespace OHOS {
namespace UserIam {
namespace UserAuth {

UserAuthCallbackV10::~UserAuthCallbackV10()
{}

void UserAuthCallbackV10::SetResultCallback(const userAuth::IAuthCallback &resultCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = Common::MakeShared<userAuth::IAuthCallback>(resultCallback);
}

void UserAuthCallbackV10::ClearResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = nullptr;
}

bool UserAuthCallbackV10::HasResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return resultCallback_ != nullptr;
}

void UserAuthCallbackV10::SetTipCallback(taihe::optional<AuthTipCallback> tipCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    tipCallback_ = Common::MakeShared<taihe::optional<AuthTipCallback>>(tipCallback);
}

void UserAuthCallbackV10::ClearTipCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    tipCallback_ = nullptr;
}

AuthTipCallbackPtr UserAuthCallbackV10::GetTipCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return tipCallback_;
}

bool UserAuthCallbackV10::HasTipCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return tipCallback_ != nullptr;
}

void UserAuthCallbackV10::SetAcquireInfoCallback(taihe::optional<AcquireInfoCallback> acquireInfoCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    acquireInfoCallback_ = Common::MakeShared<taihe::optional<AcquireInfoCallback>>(acquireInfoCallback);
}

void UserAuthCallbackV10::ClearAcquireInfoCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    acquireInfoCallback_ = nullptr;
}

AcquireInfoCallbackPtr UserAuthCallbackV10::GetAcquireInfoCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return acquireInfoCallback_;
}

bool UserAuthCallbackV10::HasAcquireInfoCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return acquireInfoCallback_ != nullptr;
}

bool UserAuthCallbackV10::DoResultCallback(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start");
    ::taihe::env_guard guard;
    if (guard.get_env() == nullptr) {
        IAM_LOGE("attach ani env fail, drop result");
        return false;
    }
    std::shared_ptr<userAuth::IAuthCallback> resultCallback = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        resultCallback = resultCallback_;
    }
    if (resultCallback == nullptr) {
        IAM_LOGI("resultCallback_ is nullptr.");
        return false;
    }

    userAuth::UserAuthResult userAuthResult = {};
    UserAuthResultCode ret = UserAuthParamUtils::GetUserAuthResult(result, extraInfo, userAuthResult);
    if (ret != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("GetUserAuthResult failed %{public}d", ret);
        return false;
    }
    resultCallback->onResult(userAuthResult);
    return true;
}

bool UserAuthCallbackV10::DoTipInfoCallBack(int32_t tipType, uint32_t tipCode)
{
    IAM_LOGI("DoTipInfoCallBack start, authType:%{public}d, tipCode:%{public}u", tipType, tipCode);
    ::taihe::env_guard guard;
    if (guard.get_env() == nullptr) {
        IAM_LOGE("attach ani env fail, drop tip info");
        return false;
    }
    auto tipCallback = GetTipCallback();
    if (tipCallback == nullptr || !tipCallback->has_value()) {
        IAM_LOGE("tipCallback is null or has no value");
        return false;
    }
    userAuth::AuthTipInfo authTipInfo = {
        userAuth::UserAuthType::key_t::PIN, userAuth::UserAuthTipCode::key_t::COMPARE_FAILURE};
    if (UserAuthHelper::CheckUserAuthType(tipType)) {
        userAuth::UserAuthType tipTypeAni(userAuth::UserAuthType::key_t::PIN);
        if (!UserAuthAniHelper::ConvertUserAuthType(tipType, tipTypeAni)) {
            IAM_LOGE("Set authType error. authType: %{public}d", tipType);
            return false;
        }
        authTipInfo.tipType = tipTypeAni;

        userAuth::UserAuthTipCode tipCodeAni(userAuth::UserAuthTipCode::key_t::COMPARE_FAILURE);
        if (!UserAuthAniHelper::ConvertUserAuthTipCode(tipCode, tipCodeAni)) {
            IAM_LOGE("Set tipCode error. tipCode: %{public}d", tipCode);
            return false;
        }
        authTipInfo.tipCode = tipCodeAni;
        (**tipCallback)(authTipInfo);
        return true;
    }
    return false;
}

bool UserAuthCallbackV10::DoAcquireInfoCallBack(int32_t module, int32_t acquireInfo,
    const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGD("start, module:%{public}d, acquireInfo:%{public}d, extraInfo len:%{public}zu", module, acquireInfo,
        extraInfo.size());
    auto acquireInfoCallback = GetAcquireInfoCallback();
    if (acquireInfoCallback == nullptr || !acquireInfoCallback->has_value()) {
        IAM_LOGI("acquireInfoCallback is null or has no value");
        return false;
    }
    ::taihe::env_guard guard;
    if (guard.get_env() == nullptr) {
        IAM_LOGE("attach ani env fail, drop acquire info");
        return false;
    }
    userAuth::AuthTipInfo authTipInfo = {
        userAuth::UserAuthType::key_t::PIN, userAuth::UserAuthTipCode::key_t::COMPARE_FAILURE};
    userAuth::UserAuthType tipTypeAni(userAuth::UserAuthType::key_t::PIN);
    if (!UserAuthAniHelper::ConvertUserAuthType(module, tipTypeAni)) {
        IAM_LOGI("drop non-standard tip, module:%{public}d, acquireInfo:%{public}d", module, acquireInfo);
        return false;
    }
    authTipInfo.tipType = tipTypeAni;
    userAuth::UserAuthTipCode tipCodeAni(userAuth::UserAuthTipCode::key_t::COMPARE_FAILURE);
    if (!UserAuthAniHelper::ConvertUserAuthTipCode(acquireInfo, tipCodeAni)) {
        IAM_LOGI("drop non-standard tip, module:%{public}d, acquireInfo:%{public}d", module, acquireInfo);
        return false;
    }
    authTipInfo.tipCode = tipCodeAni;
    authTipInfo.extraInfo = taihe::optional<taihe::array<uint8_t>>(
        std::in_place_t{}, taihe::copy_data_t{}, extraInfo.data(), extraInfo.size());
    (**acquireInfoCallback)(authTipInfo);
    return true;
}

void UserAuthCallbackV10::OnAcquireInfo(
    int32_t module, uint32_t acquireInfo, const UserIam::UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("start, authType:%{public}d, tipCode:%{public}u", module, acquireInfo);
    bool ret = DoTipInfoCallBack(module, acquireInfo);
    IAM_LOGD("DoTipInfoCallBack ret = %{public}d", ret);
    if (!HasAcquireInfoCallback()) {
        return;
    }
    bool acquireRet = DoAcquireInfoCallBack(module, static_cast<int32_t>(acquireInfo), extraInfo.Serialize());
    IAM_LOGD("DoAcquireInfoCallBack ret = %{public}d", acquireRet);
}

void UserAuthCallbackV10::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", result);
    bool cbRet = DoResultCallback(result, extraInfo);
    IAM_LOGD("DoResultCallback ret = %{public}d", cbRet);
}

}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS
 

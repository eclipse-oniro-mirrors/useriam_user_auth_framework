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
#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_auth_client_impl.h"
#include "user_auth_helper.h"
#include "user_auth_ani_helper.h"

#define LOG_FILE_ID LOG_FILE_USER_AUTH_CALLBACK_V10_ANI
#define LOG_TAG "USER_AUTH_ANI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

UserAuthCallbackV10::UserAuthCallbackV10()
{}

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

bool UserAuthCallbackV10::DoResultCallback(
    int32_t result, const std::vector<uint8_t> &token, int32_t authType, EnrolledState enrolledState)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    if (resultCallback_ == nullptr) {
        IAM_LOGI("resultCallback_ is nullptr.");
        return false;
    }
    userAuth::UserAuthResult userAuthResult = {0};
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
            return false;
        }
        userAuthResult.authType = taihe::optional<userAuth::UserAuthType>::make(authTypeAni);
    }
    if (UserAuthResultCode(result) == UserAuthResultCode::SUCCESS) {
        userAuth::EnrolledState enrolledStateAni = {enrolledState.credentialDigest, enrolledState.credentialCount};
        userAuthResult.enrolledState = taihe::optional<userAuth::EnrolledState>::make(enrolledStateAni);
    }
    resultCallback_->onResult(userAuthResult);
    return true;
}

bool UserAuthCallbackV10::DoTipInfoCallBack(int32_t tipType, uint32_t tipCode)
{
    IAM_LOGI("DoTipInfoCallBack start, authType:%{public}d, tipCode:%{public}u", tipType, tipCode);
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

void UserAuthCallbackV10::OnAcquireInfo(
    int32_t module, uint32_t acquireInfo, const UserIam::UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("start, authType:%{public}d, tipCode:%{public}u", module, acquireInfo);
    bool ret = DoTipInfoCallBack(module, acquireInfo);
    IAM_LOGD("DoResultCallback ret = %{public}d", ret);
}

void UserAuthCallbackV10::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", result);
    std::vector<uint8_t> token = {};
    int32_t authType = {0};
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
    bool ret = DoResultCallback(result, token, authType, enrolledState);
    IAM_LOGD("DoResultCallback ret = %{public}d", ret);
}

}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS
 

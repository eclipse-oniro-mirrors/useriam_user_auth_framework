/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "user_auth_remote_auth_callback.h"

#include "iam_logger.h"
#include "iam_ptr.h"
#include "attributes.h"
#include "user_auth_modal_callback.h"
#include "user_auth_param_utils.h"
#include "user_auth_helper.h"
#include "user_auth_ani_helper.h"

#define LOG_TAG "USER_AUTH_ANI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
RemoteAuthCallback::RemoteAuthCallback(const userAuth::IRemoteAuthCallback &callback)
{
    callback_ = Common::MakeShared<userAuth::IRemoteAuthCallback>(callback);
}

RemoteAuthCallback::~RemoteAuthCallback()
{}

bool RemoteAuthCallback::DoGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
    userAuth::WidgetParam &widgetParam)
{
    IAM_LOGI("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return false;
    }

    taihe::array<uint8_t> challengeArray =
        taihe::array<uint8_t>(taihe::copy_data_t{}, challenge.data(), challenge.size());
    widgetParam = callback_->onGetRemoteAuthWidgetParam(challengeArray);
    return true;
}

bool RemoteAuthCallback::DoRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t resultCode,
    const Attributes &extraInfo)
{
    IAM_LOGI("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return false;
    }
    taihe::array<uint8_t> challengeArray =
        taihe::array<uint8_t>(taihe::copy_data_t{}, challenge.data(), challenge.size());
    std::vector<uint8_t> token = {};
    int32_t authType = 0;
    EnrolledState enrolledState = {};

    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token)) {
        IAM_LOGE("ATTR_SIGNATURE is null");
        return false;
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_AUTH_TYPE, authType)) {
        IAM_LOGE("ATTR_AUTH_TYPE is null");
        return false;
    }
    if (!extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, enrolledState.credentialDigest)) {
        IAM_LOGE("ATTR_CREDENTIAL_DIGEST is null");
        return false;
    }
    if (!extraInfo.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, enrolledState.credentialCount)) {
        IAM_LOGE("ATTR_CREDENTIAL_COUNT is null");
        return false;
    }

    userAuth::UserAuthResult userAuthResult = {};
    userAuthResult.result = resultCode;
    if (!token.empty()) {
        userAuthResult.token = taihe::optional<taihe::array<uint8_t>>(
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
    userAuth::EnrolledState enrolledStateAni = {enrolledState.credentialDigest, enrolledState.credentialCount};
    userAuthResult.enrolledState = taihe::optional<userAuth::EnrolledState>::make(enrolledStateAni);

    callback_->onRemoteAuthResult(challengeArray, userAuthResult);
    return true;
}

void RemoteAuthCallback::OnGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
    const std::shared_ptr<SetWidgetParamClientCallback> &callback)
{
    IAM_LOGI("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return;
    }
    
    userAuth::WidgetParam widgetParam = {};
    bool ret = DoGetRemoteAuthWidgetParam(challenge, widgetParam);
    if (!ret) {
        IAM_LOGE("DoGetRemoteAuthWidgetParam failed");
        return;
    }

    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    WidgetParamNapi widgetParamNapi = {};
    UserAuthParamUtils::InitWidgetParam(widgetParam, widgetParamNapi, context);
    auto modalCallback = Common::MakeShared<UserAuthModalCallback>(context);
    if (modalCallback == nullptr) {
        IAM_LOGE("modalCallback is nullptr");
        return;
    }
    callback->OnSetRemoteAuthWidgetParam(widgetParamNapi, modalCallback);
}

void RemoteAuthCallback::OnRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t resultCode,
    const Attributes &extraInfo)
{
    IAM_LOGI("start");
    bool ret = DoRemoteAuthResult(challenge, resultCode, extraInfo);
    if (!ret) {
        IAM_LOGE("DoRemoteAuthResult failed");
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS


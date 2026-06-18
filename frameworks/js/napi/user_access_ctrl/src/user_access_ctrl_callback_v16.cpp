/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "user_access_ctrl_callback_v16.h"

#include <uv.h>

#include "napi/native_node_api.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_CALLBACK_V16
#define LOG_TAG "USER_ACCESS_CTRL_NAPI"

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {
namespace {
struct ResultCallbackV16Holder {
    std::shared_ptr<UserAccessCtrlCallbackV16> callback {nullptr};
    int32_t result {0};
    AuthToken authToken {};
    napi_env env {nullptr};
};
}

UserAccessCtrlCallbackV16::UserAccessCtrlCallbackV16(napi_env env, napi_deferred promise)
    : env_(env), promise_(promise)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAccessCtrlCallbackV16 get null env");
    }
}

UserAccessCtrlCallbackV16::~UserAccessCtrlCallbackV16()
{
}

napi_status UserAccessCtrlCallbackV16::ProcessAuthTokenResult(napi_env env, napi_value value, AuthToken authToken)
{
    IAM_LOGI("start");
    napi_status ret = UserAuth::UserAuthNapiHelper::SetUint8ArrayProperty(env, value, "challenge", authToken.challenge);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAuth::UserAuthNapiHelper::SetUint32Property(env, value, "authTrustLevel", authToken.authTrustLevel);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAuth::UserAuthNapiHelper::SetInt32Property(env, value, "authType", authToken.authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAuth::UserAuthNapiHelper::SetInt32Property(env, value, "tokenType", authToken.tokenType);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAuth::UserAuthNapiHelper::SetInt32Property(env, value, "userId", authToken.userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAccessCtrlNapiHelper::SetUint64Property(env, value, "timeInterval", authToken.timeInterval);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAccessCtrlNapiHelper::SetUint64Property(env, value, "secureUid", authToken.secureUid);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAccessCtrlNapiHelper::SetUint64Property(env, value, "enrolledId", authToken.enrolledId);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAccessCtrlNapiHelper::SetUint64Property(env, value, "credentialId", authToken.credentialId);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    return ret;
}

napi_status UserAccessCtrlCallbackV16::DoResultPromise(int32_t result, AuthToken authToken)
{
    if (promise_ == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value eventInfo;
    napi_status ret = napi_create_object(env_, &eventInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    if (UserAuth::UserAuthResultCode(result) == UserAuth::UserAuthResultCode::SUCCESS) {
        ret = ProcessAuthTokenResult(env_, eventInfo, authToken);
        if (ret != napi_ok) {
            IAM_LOGE("ProcessAuthTokenResult failed %{public}d", ret);
            return ret;
        }
        ret = napi_resolve_deferred(env_, promise_, eventInfo);
        if (ret != napi_ok) {
            IAM_LOGE("napi_resolve_deferred failed %{public}d", ret);
        }
    } else {
        ret = napi_reject_deferred(env_, promise_, UserAuth::UserAuthNapiHelper::GenerateBusinessErrorV9(env_,
            UserAuth::UserAuthResultCode(result)));
        if (ret != napi_ok) {
            IAM_LOGE("napi_reject_deferred failed %{public}d", ret);
        }
    }
    return ret;
}

void GetCallbackResult(const UserAuth::Attributes &extraInfo, std::shared_ptr<ResultCallbackV16Holder> resultHolder)
{
    if (!extraInfo.GetUint8ArrayValue(UserAuth::Attributes::ATTR_CHALLENGE, resultHolder->authToken.challenge)) {
        IAM_LOGE("ATTR_CHALLENGE is null");
    }
    if (!extraInfo.GetUint32Value(UserAuth::Attributes::ATTR_AUTH_TRUST_LEVEL,
        resultHolder->authToken.authTrustLevel)) {
        IAM_LOGE("ATTR_AUTH_TRUST_LEVEL is null");
    }
    if (!extraInfo.GetInt32Value(UserAuth::Attributes::ATTR_AUTH_TYPE, resultHolder->authToken.authType)) {
        IAM_LOGE("ATTR_AUTH_TYPE is null");
    }
    if (!extraInfo.GetInt32Value(UserAuth::Attributes::ATTR_TOKEN_TYPE, resultHolder->authToken.tokenType)) {
        IAM_LOGE("ATTR_TOKEN_TYPE is null");
    }
    if (!extraInfo.GetInt32Value(UserAuth::Attributes::ATTR_USER_ID, resultHolder->authToken.userId)) {
        IAM_LOGE("ATTR_USER_ID is null");
    }
    if (!extraInfo.GetUint64Value(UserAuth::Attributes::ATTR_TOKEN_TIME_INTERVAL,
        resultHolder->authToken.timeInterval)) {
        IAM_LOGE("ATTR_TOKEN_TIME_INTERVAL is null");
    }
    if (!extraInfo.GetUint64Value(UserAuth::Attributes::ATTR_SEC_USER_ID, resultHolder->authToken.secureUid)) {
        IAM_LOGE("ATTR_SEC_USER_ID is null");
    }
    if (!extraInfo.GetUint64Value(UserAuth::Attributes::ATTR_CREDENTIAL_DIGEST, resultHolder->authToken.enrolledId)) {
        IAM_LOGE("ATTR_CREDENTIAL_DIGEST is null");
    }
    if (!extraInfo.GetUint64Value(UserAuth::Attributes::ATTR_CREDENTIAL_ID, resultHolder->authToken.credentialId)) {
        IAM_LOGE("ATTR_CREDENTIAL_ID is null");
    }
}

void UserAccessCtrlCallbackV16::OnResult(int32_t result, const UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", result);
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail, napiStatus=%{public}d", napiStatus);
        return;
    }
    std::shared_ptr<ResultCallbackV16Holder> resultHolder = Common::MakeShared<ResultCallbackV16Holder>();
    if (resultHolder == nullptr) {
        IAM_LOGE("resultHolder is null");
        return;
    }
    resultHolder->callback = shared_from_this();
    resultHolder->result = UserAccessCtrlNapiHelper::GetResultCodeV16(result);
    resultHolder->env = env_;
    GetCallbackResult(extraInfo, resultHolder);
    auto task = [resultHolder] () {
        IAM_LOGI("start");
        if (resultHolder == nullptr || resultHolder->callback == nullptr) {
            IAM_LOGE("resultHolder is invalid");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(resultHolder->env, &scope);
        if (scope == nullptr) {
            IAM_LOGE("scope is invalid");
            return;
        }
        napi_status ret = resultHolder->callback->DoResultPromise(resultHolder->result, resultHolder->authToken);
        if (ret != napi_ok) {
            IAM_LOGE("DoResultPromise fail %{public}d", ret);
            napi_close_handle_scope(resultHolder->env, scope);
            return;
        }
        napi_close_handle_scope(resultHolder->env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::UserAccessCtrlCallbackV16::OnResult")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}
} // namespace UserAccessCtrl
} // namespace UserIam
} // namespace OHOS

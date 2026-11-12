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
#include "user_auth_helper.h"

#define LOG_TAG "USER_ACCESS_CTRL_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_CALLBACK_V16

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {
namespace {
struct ResultCallbackV16Holder {
    std::shared_ptr<UserAccessCtrlCallbackV16> callback {nullptr};
    int32_t result {0};
    AuthToken authToken {};
    std::vector<uint8_t> rawToken {};
    UserAuth::TokenSchedule schedule {};
    bool hasSchedule {false};
    napi_env env {nullptr};
};

napi_status DoPromiseResult(const std::shared_ptr<ResultCallbackV16Holder> &resultHolder)
{
    if (resultHolder->callback->GetPromiseResultType() ==
        UserAccessCtrlCallbackV16::PromiseResultType::RAW_TOKEN) {
        return resultHolder->callback->DoRawTokenPromise(resultHolder->result, resultHolder->rawToken);
    }
    return resultHolder->callback->DoResultPromise(resultHolder->result, resultHolder->authToken,
        resultHolder->schedule, resultHolder->hasSchedule);
}

napi_status BuildScheduleObject(napi_env env, UserAccessCtrlCallbackV16 &callback,
    const UserAuth::TokenSchedule &schedule, napi_value &scheduleObj)
{
    napi_status ret = napi_create_object(env, &scheduleObj);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    ret = callback.ProcessTokenSchedule(env, scheduleObj, schedule);
    if (ret != napi_ok) {
        IAM_LOGE("ProcessTokenSchedule failed %{public}d", ret);
    }
    return ret;
}
}

UserAccessCtrlCallbackV16::UserAccessCtrlCallbackV16(napi_env env, napi_deferred promise,
    PromiseResultType type, ResultCodeTable table)
    : env_(env), promise_(promise), type_(type), table_(table)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAccessCtrlCallbackV16 get null env");
    }
}

UserAccessCtrlCallbackV16::~UserAccessCtrlCallbackV16()
{
}

napi_status UserAccessCtrlCallbackV16::RejectWithGeneralError()
{
    napi_status ret = napi_reject_deferred(env_, promise_,
        UserAuth::UserAuthNapiHelper::GenerateBusinessErrorV9(env_,
            UserAuth::UserAuthResultCode::GENERAL_ERROR));
    if (ret != napi_ok) {
        IAM_LOGE("napi_reject_deferred failed %{public}d", ret);
    }
    return ret;
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

napi_status UserAccessCtrlCallbackV16::ProcessTokenSchedule(napi_env env, napi_value value,
    const UserAuth::TokenSchedule &schedule)
{
    IAM_LOGI("start");
    napi_status ret = napi_ok;
    if (schedule.hasValidStartTime) {
        ret = UserAuth::UserAuthNapiHelper::SetInt64Property(env, value, "validStartTime",
            schedule.validStartTime);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    }
    if (schedule.hasValidEndTime) {
        ret = UserAuth::UserAuthNapiHelper::SetInt64Property(env, value, "validEndTime",
            schedule.validEndTime);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    }
    if (schedule.windowConfig.has_value()) {
        napi_value windowConfigObj = nullptr;
        ret = napi_create_object(env, &windowConfigObj);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
        ret = UserAuth::UserAuthNapiHelper::SetInt64Property(env, windowConfigObj, "repeatInterval",
            schedule.windowConfig->repeatInterval);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
        ret = UserAuth::UserAuthNapiHelper::SetInt64Property(env, windowConfigObj, "windowDuration",
            schedule.windowConfig->windowDuration);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
        ret = napi_set_named_property(env, value, "windowConfig", windowConfigObj);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    }
    return ret;
}

napi_status UserAccessCtrlCallbackV16::DoRawTokenPromise(int32_t result, const std::vector<uint8_t> &token)
{
    if (promise_ == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    if (UserAuth::UserAuthResultCode(result) != UserAuth::UserAuthResultCode::SUCCESS) {
        napi_status ret = napi_reject_deferred(env_, promise_,
            UserAuth::UserAuthNapiHelper::GenerateBusinessErrorV9(env_, UserAuth::UserAuthResultCode(result)));
        if (ret != napi_ok) {
            IAM_LOGE("napi_reject_deferred failed %{public}d", ret);
        }
        return ret;
    }
    std::vector<uint8_t> tokenCopy = token;
    napi_value tokenValue = UserAuth::UserAuthNapiHelper::Uint8VectorToNapiUint8Array(env_, tokenCopy);
    if (tokenValue == nullptr) {
        IAM_LOGE("Uint8VectorToNapiUint8Array failed");
        return RejectWithGeneralError();
    }
    napi_status ret = napi_resolve_deferred(env_, promise_, tokenValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_resolve_deferred failed %{public}d", ret);
        return RejectWithGeneralError();
    }
    return ret;
}

napi_status UserAccessCtrlCallbackV16::DoResultPromise(int32_t result, AuthToken authToken,
    const UserAuth::TokenSchedule &schedule, bool hasSchedule)
{
    if (promise_ == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    if (UserAuth::UserAuthResultCode(result) != UserAuth::UserAuthResultCode::SUCCESS) {
        napi_status ret = napi_reject_deferred(env_, promise_,
            UserAuth::UserAuthNapiHelper::GenerateBusinessErrorV9(env_, UserAuth::UserAuthResultCode(result)));
        if (ret != napi_ok) {
            IAM_LOGE("napi_reject_deferred failed %{public}d", ret);
        }
        return ret;
    }
    napi_value eventInfo = nullptr;
    napi_status ret = napi_create_object(env_, &eventInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return RejectWithGeneralError();
    }
    ret = ProcessAuthTokenResult(env_, eventInfo, authToken);
    if (ret != napi_ok) {
        IAM_LOGE("ProcessAuthTokenResult failed %{public}d", ret);
        return RejectWithGeneralError();
    }
    if (hasSchedule) {
        napi_value scheduleObj = nullptr;
        ret = BuildScheduleObject(env_, *this, schedule, scheduleObj);
        if (ret != napi_ok) {
            return RejectWithGeneralError();
        }
        ret = napi_set_named_property(env_, eventInfo, "schedule", scheduleObj);
        if (ret != napi_ok) {
            IAM_LOGE("napi_set_named_property failed %{public}d", ret);
            return RejectWithGeneralError();
        }
    } else {
        IAM_LOGD("schedule attribute is absent, token is not a scheduled auth token");
    }
    ret = napi_resolve_deferred(env_, promise_, eventInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_resolve_deferred failed %{public}d", ret);
        return RejectWithGeneralError();
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
    if (!extraInfo.GetUint8ArrayValue(UserAuth::Attributes::ATTR_SIGNATURE, resultHolder->rawToken)) {
        IAM_LOGD("ATTR_SIGNATURE is null");
    }
    UserAuth::TokenSchedule schedule = {};
    if (UserAuth::UserAuthHelper::GetTokenScheduleAttr(extraInfo, schedule)) {
        resultHolder->schedule = schedule;
        resultHolder->hasSchedule = true;
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
    if (GetResultCodeTable() == ResultCodeTable::V26) {
        resultHolder->result = static_cast<int32_t>(UserAuth::UserAuthHelper::GetResultCodeV26(result));
    } else {
        resultHolder->result = static_cast<int32_t>(UserAuth::UserAuthHelper::GetResultCodeV16(result));
    }
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
        napi_status ret = DoPromiseResult(resultHolder);
        if (ret != napi_ok) {
            IAM_LOGE("DoPromiseResult fail %{public}d", ret);
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

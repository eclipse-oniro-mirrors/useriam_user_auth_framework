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

#include "user_access_ctrl_instance_v16.h"

#include <algorithm>
#include <cinttypes>
#include <string>

#include "iam_common_defines.h"
#include "iam_logger.h"

#include "user_access_ctrl_client_impl.h"

#define LOG_TAG "USER_ACCESS_CTRL_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_INSTANCE_V16

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {
namespace {
bool ParseVerifyAuthTokenParams(napi_env env, const napi_value *argv, std::vector<uint8_t> &tokenIn,
    uint32_t &duration)
{
    if (UserAuth::UserAuthNapiHelper::GetUint8ArrayValue(env, argv[PARAM0], UserAuth::MAX_AUTH_TOKEN_LEN,
        tokenIn) != napi_ok) {
        IAM_LOGE("GetUint8ArrayValue fail");
        std::string msgStr = "Parameter error. The length of \"authToken\" cannot exceed 1024.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return false;
    }
    if (tokenIn.empty()) {
        IAM_LOGE("tokenIn is empty");
        std::string msgStr = "Parameter error. \"authToken\" must be non-empty.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return false;
    }
    if (UserAuth::UserAuthNapiHelper::GetUint32Value(env, argv[PARAM1], duration) != napi_ok) {
        IAM_LOGE("GetUint32Value fail");
        std::string msgStr = "Parameter error. The type of \"allowableDuration\" must be number.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return false;
    }
    if (!UserAccessCtrlNapiHelper::CheckAllowableDuration(duration)) {
        IAM_LOGE("CheckAllowableDuration fail");
        std::string msgStr = "Parameter error. The range of \"allowableDuration\" must be between 0 and 86400000.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return false;
    }
    return true;
}
} // namespace

napi_value UserAccessCtrlInstanceV16::VerifyAuthToken(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGS_TWO] = {nullptr};
    size_t argc = ARGS_TWO;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    napi_value retPromise = nullptr;
    napi_deferred promiseDeferred = nullptr;
    if (argc != ARGS_TWO) {
        IAM_LOGE("parms error");
        std::string msgStr = "Parameter error. The number of parameters should be 2.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }
    NAPI_CALL(env, napi_create_promise(env, &promiseDeferred, &retPromise));
    std::shared_ptr<UserAccessCtrlCallbackV16> callback_ = Common::MakeShared<UserAccessCtrlCallbackV16>(env,
        promiseDeferred, UserAccessCtrlCallbackV16::PromiseResultType::AUTH_TOKEN,
        UserAccessCtrlCallbackV16::ResultCodeTable::V26);
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateBusinessErrorV9(env,
        UserAuth::UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    std::vector<uint8_t> tokenIn;
    uint32_t duration = 0;
    if (!ParseVerifyAuthTokenParams(env, argv, tokenIn, duration)) {
        return nullptr;
    }
    UserAuth::UserAccessCtrlClientImpl::GetInstance().VerifyAuthToken(tokenIn, duration, callback_);
    return retPromise;
}

napi_value UserAccessCtrlInstanceV16::RedeemScheduledAuthToken(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGS_TWO] = {nullptr};
    size_t argc = ARGS_TWO;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_TWO) {
        IAM_LOGE("parms error");
        std::string msgStr = "Parameter error. The number of parameters should be 2.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }
    std::vector<uint8_t> challenge;
    if (UserAuth::UserAuthNapiHelper::GetUint8ArrayValue(env, argv[PARAM0], UserAuth::MAX_CHALLENG_LEN,
        challenge) != napi_ok || challenge.empty()) {
        IAM_LOGE("challenge is empty or invalid");
        std::string msgStr = "Parameter error. \"challenge\" must be non-empty and cannot exceed 32 bytes.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }
    std::vector<uint8_t> scheduleToken;
    if (UserAuth::UserAuthNapiHelper::GetUint8ArrayValue(env, argv[PARAM1], UserAuth::MAX_AUTH_TOKEN_LEN,
        scheduleToken) !=
        napi_ok) {
        IAM_LOGE("GetUint8ArrayValue fail");
        std::string msgStr = "Parameter error. The length of \"scheduledAuthToken\" cannot exceed 1024.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }
    napi_value retPromise = nullptr;
    napi_deferred promiseDeferred = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &promiseDeferred, &retPromise));
    std::shared_ptr<UserAccessCtrlCallbackV16> callback_ = Common::MakeShared<UserAccessCtrlCallbackV16>(env,
        promiseDeferred, UserAccessCtrlCallbackV16::PromiseResultType::RAW_TOKEN,
        UserAccessCtrlCallbackV16::ResultCodeTable::V26);
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateBusinessErrorV9(env,
        UserAuth::UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuth::UserAccessCtrlClientImpl::GetInstance().RedeemScheduledAuthToken(challenge, scheduleToken, callback_);
    return retPromise;
}
} // namespace UserAccessCtrl
} // namespace UserIam
} // namespace OHOS

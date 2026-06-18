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

#include "iam_logger.h"

#include "user_access_ctrl_client_impl.h"

#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_INSTANCE_V16
#define LOG_TAG "USER_ACCESS_CTRL_NAPI"

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {

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
    } else {
        NAPI_CALL(env, napi_create_promise(env, &promiseDeferred, &retPromise));
    }
    std::shared_ptr<UserAccessCtrlCallbackV16> callback_ = Common::MakeShared<UserAccessCtrlCallbackV16>(env,
        promiseDeferred);
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateBusinessErrorV9(env,
        UserAuth::UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    std::vector<uint8_t> tokenIn;
    if (UserAuth::UserAuthNapiHelper::GetUint8ArrayValue(env, argv[PARAM0], MAX_AUTH_TOKEN_LEN, tokenIn) != napi_ok) {
        IAM_LOGE("GetUint8ArrayValue fail");
        std::string msgStr = "Parameter error. The length of \"tokenIn\" cannot exceed 1024.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }
    uint32_t duration;
    if (UserAuth::UserAuthNapiHelper::GetUint32Value(env, argv[PARAM1], duration) != napi_ok) {
        IAM_LOGE("GetUint32Value fail");
        std::string msgStr = "Parameter error. The type of \"allowableDuration\" must be number.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }
    uint64_t allowableDuration = duration;
    if (!UserAccessCtrlNapiHelper::CheckAllowableDuration(allowableDuration)) {
        IAM_LOGE("CheckAllowableDuration fail");
        std::string msgStr = "Parameter error. The range of \"allowableDuration\" must be between 0 and 86400000.";
        napi_throw(env, UserAuth::UserAuthNapiHelper::GenerateErrorMsg(env,
        UserAuth::UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }
    UserAuth::UserAccessCtrlClientImpl::GetInstance().VerifyAuthToken(tokenIn, allowableDuration, callback_);
    return retPromise;
}
} // namespace UserAccessCtrl
} // namespace UserIam
} // namespace OHOS

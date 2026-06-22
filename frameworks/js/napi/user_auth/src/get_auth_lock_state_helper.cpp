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

#include <uv.h>

#include "get_auth_lock_state_helper.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "napi/native_node_api.h"
#include "user_auth_helper.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_GET_AUTH_LOCK_STATE_HELPER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace GetAuthLockStateHelper {
napi_status GetAuthLockStateCompleteInner(napi_env env, GetAuthLockStateAsyncHolder *asyncHolder,
    napi_value &authLockStateResult)
{
    IAM_LOGI("start");
    if (asyncHolder->status != napi_ok) {
        IAM_LOGI("status in asyncHolder not success");
        return asyncHolder->status;
    }

    napi_status ret = napi_create_object(env, &authLockStateResult);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAuth::UserAuthNapiHelper::SetBoolProperty(env, authLockStateResult, "isLocked",
        asyncHolder->authLockState.isLocked);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAuth::UserAuthNapiHelper::SetInt32Property(env, authLockStateResult, "remainingAuthAttempts",
        asyncHolder->authLockState.remainingAuthAttempts);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    ret = UserAuth::UserAuthNapiHelper::SetInt32Property(env, authLockStateResult, "lockoutDuration",
        asyncHolder->authLockState.lockoutDuration);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == napi_ok, ret);
    return napi_ok;
}

void GetAuthLockStateComplete(napi_env env, GetAuthLockStateAsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    if (asyncHolder == nullptr) {
        IAM_LOGE("GetAuthLockStateComplete asyncHolder is nullptr, failed.");
        return;
    }
    napi_value authLockStateResult;
    napi_status ret = napi_ok;
    if (GetAuthLockStateCompleteInner(env, asyncHolder, authLockStateResult) != napi_ok) {
        IAM_LOGE("GetAuthLockStateCompleteInner reject deferred.");
        auto resultCode = UserAuthHelper::GetResultCodeV21(asyncHolder->resultCode);
        ret = napi_reject_deferred(env, asyncHolder->deferred,
            UserAuthNapiHelper::GenerateBusinessErrorV21(env,
            static_cast<UserAuthResultCode>(resultCode)));
        IF_FALSE_LOGE_AND_RETURN(ret == napi_ok);
    } else {
        IAM_LOGI("GetAuthLockStateCompleteInner resolve deferred.");
        ret = napi_resolve_deferred(env, asyncHolder->deferred,
            authLockStateResult);
        IF_FALSE_LOGE_AND_RETURN(ret == napi_ok);
    }

    return;
}

void GetAuthLockStateExecute(GetAuthLockStateAsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    if (asyncHolder == nullptr) {
        IAM_LOGE("GetAuthLockStateExecute asyncHolder is nullptr, failed.");
        return;
    }
    std::shared_ptr<GetAuthLockStateCallbackV21> getAuthLockStateCallback =
        Common::MakeShared<GetAuthLockStateCallbackV21>();
    if (getAuthLockStateCallback == nullptr) {
        IAM_LOGE("getAuthLockStateCallback is nullptr failed.");
        asyncHolder->status = napi_generic_failure;
        asyncHolder->resultCode = UserAuth::ResultCode::GENERAL_ERROR;
        return;
    }
    UserAuthClientImpl::Instance().GetAuthLockState(asyncHolder->authType, getAuthLockStateCallback);
    auto result = getAuthLockStateCallback->WaitResult();
    if (result != UserAuth::ResultCode::SUCCESS) {
        asyncHolder->resultCode = result;
        asyncHolder->status = napi_generic_failure;
        IAM_LOGE("GetAuthLockState failed.");
        return;
    }
    getAuthLockStateCallback->ProcessAuthLockStateResult(asyncHolder);
    IAM_LOGI("end");
}

bool ParseGetAuthLockStateParams(napi_env env, napi_callback_info info,
    GetAuthLockStateAsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    napi_value argv[ARGS_ONE] = {nullptr};
    size_t argc = ARGS_ONE;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (argc != ARGS_ONE) {
        asyncHolder->errMsg = "Parameter error. The number of parameters should be 1.";
        asyncHolder->resultCode = ResultCode::INVALID_PARAMETERS;
        return false;
    }

    int32_t type{0};
    if (UserAuthNapiHelper::GetInt32Value(env, argv[PARAM0], type) != napi_ok) {
        asyncHolder->errMsg = "napi get int32 value failed.";
        asyncHolder->resultCode = ResultCode::INVALID_PARAMETERS;
        return false;
    }

    if (!UserAuthHelper::CheckUserAuthType(type)) {
        asyncHolder->errMsg = "param check user auth type failed.";
        asyncHolder->resultCode = ResultCode::TYPE_NOT_SUPPORT;
        return false;
    }

    asyncHolder->authType = AuthType(type);
    return true;
}

bool GetAuthLockStateWork(napi_env env, GetAuthLockStateAsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    napi_value resourceName = nullptr;
    NAPI_CALL_BASE(env, napi_create_string_utf8(env, "GetAuthLockState", NAPI_AUTO_LENGTH, &resourceName), false);
    auto status = napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            GetAuthLockStateAsyncHolder *authLockStateAsyncHolder =
                reinterpret_cast<GetAuthLockStateAsyncHolder *>(data);
            GetAuthLockStateExecute(authLockStateAsyncHolder);
        },
        [](napi_env env, napi_status status, void *data) {
            GetAuthLockStateAsyncHolder *authLockStateAsyncHolder =
                reinterpret_cast<GetAuthLockStateAsyncHolder *>(data);
            if (status == napi_ok) {
                GetAuthLockStateComplete(env, authLockStateAsyncHolder);
            } else {
                IAM_LOGE("execute failed with status: %d", status);
                if (authLockStateAsyncHolder != nullptr && authLockStateAsyncHolder->deferred != nullptr) {
                    napi_value error_msg;
                    napi_create_string_utf8(env, "execute operation failed", NAPI_AUTO_LENGTH, &error_msg);
                    napi_reject_deferred(env, authLockStateAsyncHolder->deferred, error_msg);
                }
            }

            if (authLockStateAsyncHolder->work != nullptr) {
                auto ret = napi_delete_async_work(env, authLockStateAsyncHolder->work);
                IF_FALSE_LOGE_AND_RETURN(ret == napi_ok);
            }
            delete authLockStateAsyncHolder;
        },
        asyncHolder, &asyncHolder->work);
    if (status != napi_ok) {
        IAM_LOGE("napi_create_async_work failed.");
        return false;
    }
    status = napi_queue_async_work_with_qos(env, asyncHolder->work, napi_qos_user_initiated);
    if (status != napi_ok) {
        NAPI_CALL_BASE(env, napi_delete_async_work(env, asyncHolder->work), false);
        IAM_LOGE("napi_queue_async_work_qos failed.");
        return false;
    }
    IAM_LOGI("success");
    return true;
}
}

GetAuthLockStateCallbackV21::GetAuthLockStateCallbackV21()
{
    future_ = promise_.get_future().share();
}

GetAuthLockStateCallbackV21::~GetAuthLockStateCallbackV21()
{
}

void GetAuthLockStateCallbackV21::ProcessAuthLockStateResult(
    GetAuthLockStateHelper::GetAuthLockStateAsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    asyncHolder->resultCode = resultCode_;
    if (resultCode_ != ResultCode::SUCCESS) {
        asyncHolder->status = napi_generic_failure;
        return;
    }
    asyncHolder->authLockState.isLocked = authLockState_.isLocked;
    asyncHolder->authLockState.remainingAuthAttempts = authLockState_.remainingAuthAttempts;
    asyncHolder->authLockState.lockoutDuration = authLockState_.lockoutDuration;
}

void GetAuthLockStateCallbackV21::OnResult(int32_t result, const UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", result);
    std::lock_guard<std::mutex> guard(mutex_);
    resultCode_ = static_cast<UserAuth::ResultCode>(result);
    if (resultCode_ != UserAuth::ResultCode::SUCCESS) {
        IAM_LOGE("service resultCode is not success.");
        SetResult(resultCode_);
        return;
    }

    if (!extraInfo.GetInt32Value(UserAuth::Attributes::ATTR_REMAIN_ATTEMPTS,
        authLockState_.remainingAuthAttempts)) {
        IAM_LOGE("ATTR_REMAIN_ATTEMPTS is null");
        SetResult(UserAuth::ResultCode::GENERAL_ERROR);
        return;
    }

    if (!extraInfo.GetInt32Value(UserAuth::Attributes::ATTR_LOCKOUT_DURATION,
        authLockState_.lockoutDuration)) {
        IAM_LOGE("ATTR_LOCKOUT_DURATION is null");
        SetResult(UserAuth::ResultCode::GENERAL_ERROR);
        return;
    }
    
    authLockState_.isLocked = authLockState_.lockoutDuration > 0;
    SetResult(resultCode_);
}

void GetAuthLockStateCallbackV21::SetResult(ResultCode result)
{
    bool setted = isResultSetted_.exchange(true);
    if (setted) {
        IAM_LOGE("result already setted");
        return;
    }
    resultCode_ = result;
    promise_.set_value(result);
}

ResultCode GetAuthLockStateCallbackV21::WaitResult()
{
    constexpr int32_t maxWaitTime = 3;
    std::future_status status = future_.wait_for(std::chrono::seconds(maxWaitTime));
    if (status == std::future_status::timeout) {
        IAM_LOGE("wait result timeout");
        return UserAuth::ResultCode::TIMEOUT;
    }
    if (status == std::future_status::deferred) {
        IAM_LOGE("wait result deferred");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    if (status != std::future_status::ready) {
        IAM_LOGE("wait result exception");
        return UserAuth::ResultCode::GENERAL_ERROR;
    }
    return future_.get();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "user_auth_widget_mgr_v10.h"

#include <string>
#include <cstring>
#include "iam_logger.h"
#include "iam_ptr.h"

#include "user_auth_client_impl.h"
#include "user_auth_helper.h"
#include "user_auth_widget_callback_v10.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_WIDGET_MGR_V10_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::string TYPE_COMMAND = "command";
const std::string TYPE_RESULT = "result";
const std::string VERSION = "version";

UserAuthWidgetMgr::UserAuthWidgetMgr(napi_env env) : callback_(Common::MakeShared<UserAuthWidgetCallback>(env))
{
}

UserAuthResultCode UserAuthWidgetMgr::Init(napi_env env, napi_callback_info info)
{
    IAM_LOGI("UserAuthWidgetMgr::Init");

    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        std::string msgStr = "Parameter error. The number of parameters should be 1";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    int32_t version = 0;
    ret = UserAuthNapiHelper::GetInt32Value(env, argv[PARAM0], version);
    IAM_LOGI("UserAuthWidgetMgr version: %{public}d", version);
    if (ret != napi_ok) {
        IAM_LOGE("get version fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"version\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    if (version != WIDGET_NOTICE) {
        IAM_LOGE("version error: %{public}d", version);
        return UserAuthResultCode::TYPE_NOT_SUPPORT;
    }
    version_ = version;
    int32_t result = UserAuthClientImpl::Instance().SetWidgetCallback(version_, callback_);
    IAM_LOGD("version SetWidgetCallback result: %{public}d", result);
    return static_cast<UserAuthResultCode>(UserAuthHelper::GetResultCodeV10(result));
}

std::shared_ptr<JsRefHolder> UserAuthWidgetMgr::GetCallback(napi_env env, napi_value value)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_object);
    if (ret != napi_ok) {
        IAM_LOGE("CheckNapiType fail:%{public}d", ret);
        return nullptr;
    }
    napi_value callbackValue;
    ret = napi_get_named_property(env, value, "sendCommand", &callbackValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_named_property fail:%{public}d", ret);
        return nullptr;
    }
    return Common::MakeShared<JsRefHolder>(env, callbackValue);
}

UserAuthResultCode UserAuthWidgetMgr::On(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_TWO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        std::string msgStr = "Parameter error. The number of parameters should be 2";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    static const size_t maxLen = 10;
    char type[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], type, len);
    if (ret != napi_ok) {
        IAM_LOGE("GetStrValue fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"type\" must be string.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    auto callbackRef = GetCallback(env, argv[PARAM1]);
    if (callbackRef == nullptr || !callbackRef->IsValid()) {
        IAM_LOGE("GetCallback fail");
        std::string msgStr = "Parameter error. The type of \"callback\" must be IAuthWidgetCallback.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    if (type == TYPE_COMMAND) {
        IAM_LOGI("SetResultCallback");
        if (callback_->HasCommandCallback()) {
            IAM_LOGE("command callback has been registerred");
            return UserAuthResultCode::GENERAL_ERROR;
        }
        callback_->SetCommandCallback(callbackRef);
        return UserAuthResultCode::SUCCESS;
    } else {
        IAM_LOGE("invalid event:%{public}s", type);
        std::string msgStr = "Parameter error. The value of \"type\" must be \"command\".";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
}

UserAuthResultCode UserAuthWidgetMgr::Off(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_TWO && argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        std::string msgStr = "Parameter error. The number of parameters should be 1 or 2";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    static const size_t maxLen = 10;
    char type[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], type, len);
    if (ret != napi_ok) {
        IAM_LOGE("GetStrValue fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"type\" must be string.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    if (argc == ARGS_TWO) {
        auto callbackRef = GetCallback(env, argv[PARAM1]);
        if (callbackRef == nullptr || !callbackRef->IsValid()) {
            IAM_LOGE("GetCallback fail");
            std::string msgStr = "Parameter error. The type of \"callback\" must be IAuthCallback.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
    }

    if (type == TYPE_COMMAND) {
        IAM_LOGI("ClearResultCallback");
        if (!callback_->HasCommandCallback()) {
            IAM_LOGE("no command callback register yet");
            return UserAuthResultCode::GENERAL_ERROR;
        }
        callback_->ClearCommandCallback();
        return UserAuthResultCode::SUCCESS;
    } else {
        IAM_LOGE("invalid event:%{public}s", type);
        std::string msgStr = "Parameter error. The value of \"type\" must be \"command\".";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

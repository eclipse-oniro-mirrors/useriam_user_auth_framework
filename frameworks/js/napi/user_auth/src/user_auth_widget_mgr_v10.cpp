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
#include "user_auth_widget_callback_v10.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::string TYPE_COMMAND = "command";
const std::string TYPE_RESULT = "result";
const std::string VERSION = "version";

UserAuthWidgetMgr::UserAuthWidgetMgr(napi_env env) : callback_(Common::MakeShared<UserAuthWidgetCallback>(env))
{
    if (callback_ == nullptr) {
        IAM_LOGE("get null callback");
    }
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
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    uint32_t version = 0;
    ret = UserAuthNapiHelper::GetUint32Value(env, argv[PARAM0], version);
    IAM_LOGI("UserAuthWidgetMgr version: %{public}u", version);
    if (ret != napi_ok) {
        IAM_LOGE("get version fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    if (version != WIDGET_NOTICE) {
        IAM_LOGE("version error: %{public}d", version);
        return UserAuthResultCode::TYPE_NOT_SUPPORT;
    }
    version_ = version;
    int32_t result = UserAuthClientImpl::Instance().SetWidgetCallback(version_, callback_);
    IAM_LOGI("version SetWidgetCallback result: %{public}d", result);
    return static_cast<UserAuthResultCode>(UserAuthNapiHelper::GetResultCodeV10(result));
}

std::shared_ptr<JsRefHolder> UserAuthWidgetMgr::GetCallback(napi_env env, napi_value value)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_object);
    if (ret != napi_ok) {
        IAM_LOGE("CheckNapiType fail:%{public}d", ret);
        return nullptr;
    }
    napi_value callbackValue;
    ret = napi_get_named_property(env, value, "callback", &callbackValue);
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
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    static const size_t maxLen = 10;
    char type[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], type, len);
    if (ret != napi_ok) {
        IAM_LOGE("GetStrValue fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    auto callbackRef = GetCallback(env, argv[PARAM1]);
    if (callbackRef == nullptr || !callbackRef->IsValid()) {
        IAM_LOGE("GetCallback fail");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
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
        return UserAuthResultCode::OHOS_INVALID_PARAM;
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
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    static const size_t maxLen = 10;
    char type[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], type, len);
    if (ret != napi_ok) {
        IAM_LOGE("GetStrValue fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    if (argc == ARGS_TWO) {
        auto callbackRef = GetCallback(env, argv[PARAM1]);
        if (callbackRef == nullptr || !callbackRef->IsValid()) {
            IAM_LOGE("GetCallback fail");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
    }

    if (type == TYPE_COMMAND) {
        IAM_LOGI("SetResultCallback");
        if (!callback_->HasCommandCallback()) {
            IAM_LOGE("no command callback register yet");
            return UserAuthResultCode::GENERAL_ERROR;
        }
        callback_->ClearCommandCallback();
        return UserAuthResultCode::SUCCESS;
    } else {
        IAM_LOGE("invalid event:%{public}s", type);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "user_recognition_manager.h"

#include <algorithm>
#include <cstring>
#include <uv.h>

#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_auth_api_event_reporter.h"
#include "user_auth_helper.h"
#include "user_auth_napi_helper.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_RECOGNITION_MANAGER_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

napi_value BuildResultObject(napi_env env, const UserRecognitionResult &result)
{
    napi_value obj = nullptr;
    napi_status s = napi_create_object(env, &obj);
    if (s != napi_ok || obj == nullptr) {
        IAM_LOGE("napi_create_object fail:%{public}d", s);
        return nullptr;
    }
    UserAuthNapiHelper::SetInt32Property(env, obj, "status", static_cast<int32_t>(result.status));
    UserAuthNapiHelper::SetInt32Property(env, obj, "userId", result.userId);
    UserAuthNapiHelper::SetStringPropertyUtf8(env, obj, "userInfo", result.userInfo);
    if (result.authTrustLevel.has_value() && result.status == UserRecognitionStatus::MATCH) {
        UserAuthNapiHelper::SetUint32Property(env, obj, "authTrustLevel", *result.authTrustLevel);
    }
    return obj;
}

UserRecognitionManagerNapi *UnwrapManager(napi_env env, napi_callback_info info, size_t *argc, napi_value *argv)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, argc, argv, &thisVar, nullptr);
    void *data = nullptr;
    napi_unwrap(env, thisVar, &data);
    return static_cast<UserRecognitionManagerNapi *>(data);
}

struct UserRecognitionEventHolder {
    std::shared_ptr<UserRecognitionManagerNapi::CallbackImpl> callback {nullptr};
    UserRecognitionResult result {};
    napi_env env {nullptr};
};
} // namespace

class UserRecognitionManagerNapi::CallbackImpl : public UserRecognitionEventListener,
                                                 public std::enable_shared_from_this<CallbackImpl> {
public:
    CallbackImpl(napi_env env, napi_ref ref) : env_(env), ref_(ref) {}
    ~CallbackImpl() override
    {
        if (env_ == nullptr || ref_ == nullptr) {
            return;
        }
        napi_env env = env_;
        napi_ref ref = ref_;
        ref_ = nullptr;
        uv_loop_s *loop = nullptr;
        napi_status loopStatus = napi_get_uv_event_loop(env, &loop);
        if (loopStatus != napi_ok || loop == nullptr) {
            IAM_LOGE("napi_get_uv_event_loop fail");
            return;
        }
        auto task = [env, ref]() {
            napi_status ret = napi_delete_reference(env, ref);
            if (ret != napi_ok) {
                IAM_LOGE("napi_delete_reference fail %{public}d", ret);
            }
        };
        if (napi_status::napi_ok != napi_send_event(env, task, napi_eprio_immediate,
            "UserAuthNapi::UserRecognitionCallback::~CallbackImpl")) {
            IAM_LOGE("napi_send_event: Failed to SendEvent");
        }
    }

    void OnUserRecognitionEvent(const UserRecognitionResult &result) override
    {
        uv_loop_s *loop = nullptr;
        napi_status loopStatus = napi_get_uv_event_loop(env_, &loop);
        if (loopStatus != napi_ok || loop == nullptr) {
            IAM_LOGE("napi_get_uv_event_loop fail");
            return;
        }
        auto holder = Common::MakeShared<UserRecognitionEventHolder>();
        if (holder == nullptr) {
            IAM_LOGE("holder is null");
            return;
        }
        holder->callback = shared_from_this();
        holder->result = result;
        holder->env = env_;
        auto task = [holder]() {
            if (holder == nullptr || holder->callback == nullptr) {
                IAM_LOGE("holder is invalid");
                return;
            }
            napi_env env = holder->env;
            napi_value fn = holder->callback->GetFunction(env);
            IF_FALSE_LOGE_AND_RETURN(fn != nullptr);
            napi_handle_scope scope = nullptr;
            napi_status scopeStatus = napi_open_handle_scope(env, &scope);
            if (scopeStatus != napi_ok || scope == nullptr) {
                IAM_LOGE("napi_open_handle_scope fail");
                return;
            }
            napi_value arg = BuildResultObject(env, holder->result);
            napi_value undefined = nullptr;
            napi_get_undefined(env, &undefined);
            napi_call_function(env, undefined, fn, 1, &arg, nullptr);
            napi_close_handle_scope(env, scope);
        };
        if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
            "UserAuthNapi::UserRecognitionCallback::OnUserRecognitionEvent")) {
            IAM_LOGE("napi_send_event: Failed to SendEvent");
        }
    }

    napi_value GetFunction(napi_env env) const
    {
        if (ref_ == nullptr) {
            return nullptr;
        }
        napi_value fn = nullptr;
        napi_status s = napi_get_reference_value(env, ref_, &fn);
        if (s != napi_ok) {
            IAM_LOGE("napi_get_reference_value fail:%{public}d", s);
            return nullptr;
        }
        return fn;
    }

private:
    napi_env env_;
    napi_ref ref_;
};

UserRecognitionManagerNapi::~UserRecognitionManagerNapi()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &cb : callbacks_) {
        UserAuthClient::GetInstance().UnregisterUserRecognitionEventListener(cb);
    }
    callbacks_.clear();
}

UserRecognitionManagerNapi::CallbackList::iterator UserRecognitionManagerNapi::FindCallback(napi_env env,
    napi_value fn)
{
    return std::find_if(callbacks_.begin(), callbacks_.end(),
        [env, fn](const std::shared_ptr<CallbackImpl> &existing) {
            napi_value existingFn = existing->GetFunction(env);
            if (existingFn == nullptr) {
                return false;
            }
            bool equal = false;
            return napi_strict_equals(env, fn, existingFn, &equal) == napi_ok && equal;
        });
}

UserAuthResultCode UserRecognitionManagerNapi::RegisterCallback(napi_env env, napi_value fn)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (FindCallback(env, fn) != callbacks_.end()) {
        IAM_LOGI("callback already registered, skip");
        return UserAuthResultCode::SUCCESS;
    }
    napi_ref ref = nullptr;
    napi_status status = UserAuthNapiHelper::GetFunctionRef(env, fn, ref);
    if (status != napi_ok || ref == nullptr) {
        IAM_LOGE("create function reference fail");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    auto cb = Common::MakeShared<CallbackImpl>(env, ref);
    if (cb == nullptr) {
        IAM_LOGE("create callback fail");
        napi_status deleteRet = napi_delete_reference(env, ref);
        if (deleteRet != napi_ok) {
            IAM_LOGE("napi_delete_reference fail:%{public}d", deleteRet);
        }
        return UserAuthResultCode::GENERAL_ERROR;
    }
    int32_t ret = UserAuthClient::GetInstance().RegisterUserRecognitionEventListener(cb);
    if (ret != SUCCESS) {
        IAM_LOGE("register listener fail, ret:%{public}d", ret);
        return static_cast<UserAuthResultCode>(UserAuthHelper::GetResultCodeV10(ret));
    }
    callbacks_.push_back(cb);
    return UserAuthResultCode::SUCCESS;
}

napi_value UserRecognitionManagerNapi::Constructor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::unique_ptr<UserRecognitionManagerNapi> manager {new (std::nothrow) UserRecognitionManagerNapi()};
    if (manager == nullptr) {
        IAM_LOGE("manager is nullptr");
        return nullptr;
    }
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_CALL(env, napi_wrap(env, thisVar, manager.get(),
        [](napi_env env, void *data, void *hint) {
            auto *manager = static_cast<UserRecognitionManagerNapi *>(data);
            if (manager != nullptr) {
                delete manager;
            }
        },
        nullptr, nullptr));
    manager.release();
    return thisVar;
}

napi_value UserRecognitionManagerNapi::JsClass(napi_env env)
{
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("getUserRecognitionResult", UserRecognitionManagerNapi::GetUserRecognitionResult),
        DECLARE_NAPI_FUNCTION("onUserRecognitionChange", UserRecognitionManagerNapi::On),
        DECLARE_NAPI_FUNCTION("offUserRecognitionChange", UserRecognitionManagerNapi::Off),
    };
    napi_value result = nullptr;
    napi_define_class(env, "UserRecognitionMgr", NAPI_AUTO_LENGTH, UserRecognitionManagerNapi::Constructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &result);
    return result;
}

napi_value UserRecognitionManagerNapi::GetInstance(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthApiEventReporter reporter("GetUserRecognitionMgr");
    int32_t ret = UserAuthClient::GetInstance().CheckUserRecognitionCapability();
    if (ret == SUCCESS) {
        napi_value instance = nullptr;
        napi_status status = napi_new_instance(env, JsClass(env), 0, nullptr, &instance);
        if (status != napi_ok) {
            IAM_LOGE("napi_new_instance fail:%{public}d", status);
            napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
            reporter.ReportFailed(UserAuthResultCode::GENERAL_ERROR);
            return nullptr;
        }
        reporter.ReportSuccess();
        return instance;
    }
    if (ret == DEVICE_CAPABILITY_NOT_SUPPORT) {
        IAM_LOGI("user recognition not supported, return null");
        reporter.ReportSuccess();
        napi_value result = nullptr;
        napi_status status = napi_get_null(env, &result);
        if (status != napi_ok) {
            IAM_LOGE("napi_get_null fail:%{public}d", status);
        }
        return result;
    }
    UserAuthResultCode errorCode = static_cast<UserAuthResultCode>(UserAuthHelper::GetResultCodeV10(ret));
    IAM_LOGE("check capability fail, ret:%{public}d", ret);
    napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, errorCode));
    reporter.ReportFailed(errorCode);
    return nullptr;
}

napi_value UserRecognitionManagerNapi::GetUserRecognitionResult(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthApiEventReporter reporter("GetUserRecognitionResult");
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);
    UserRecognitionResult result;
    int32_t ret = UserAuthClient::GetInstance().GetUserRecognitionResult(result);
    if (ret != SUCCESS) {
        IAM_LOGE("get user recognition result fail, ret:%{public}d", ret);
        UserAuthResultCode errorCode = static_cast<UserAuthResultCode>(UserAuthHelper::GetResultCodeV10(ret));
        reporter.ReportFailed(errorCode);
        napi_status s = napi_reject_deferred(env, deferred,
            UserAuthNapiHelper::GenerateBusinessErrorV9(env, errorCode));
        if (s != napi_ok) {
            IAM_LOGE("napi_reject_deferred fail:%{public}d", s);
        }
        return promise;
    }
    reporter.ReportSuccess();
    napi_status resolveStatus = napi_resolve_deferred(env, deferred, BuildResultObject(env, result));
    if (resolveStatus != napi_ok) {
        IAM_LOGE("napi_resolve_deferred fail:%{public}d", resolveStatus);
    }
    return promise;
}

UserAuthResultCode UserRecognitionManagerNapi::OnInternal(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    auto *manager = UnwrapManager(env, info, &argc, argv);
    if (argc < 1) {
        IAM_LOGE("no callback");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    IF_FALSE_LOGE_AND_RETURN_VAL(manager != nullptr, UserAuthResultCode::GENERAL_ERROR);
    napi_valuetype vt = napi_undefined;
    napi_status typeofStatus = napi_typeof(env, argv[0], &vt);
    if (typeofStatus != napi_ok || vt != napi_function) {
        IAM_LOGE("callback is not a function");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    return manager->RegisterCallback(env, argv[0]);
}

napi_value UserRecognitionManagerNapi::On(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthApiEventReporter reporter("OnUserRecognitionChange");
    UserAuthResultCode code = OnInternal(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
        reporter.ReportFailed(code);
        return nullptr;
    }
    reporter.ReportSuccess();
    return nullptr;
}

UserAuthResultCode UserRecognitionManagerNapi::OffInternal(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    auto *manager = UnwrapManager(env, info, &argc, argv);
    IF_FALSE_LOGE_AND_RETURN_VAL(manager != nullptr, UserAuthResultCode::GENERAL_ERROR);
    bool clearAll = argc < 1;
    if (!clearAll) {
        napi_valuetype vt = napi_undefined;
        napi_status typeofStatus = napi_typeof(env, argv[0], &vt);
        if (typeofStatus != napi_ok) {
            IAM_LOGE("napi_typeof fail:%{public}d", typeofStatus);
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        if (vt == napi_undefined || vt == napi_null) {
            clearAll = true;
        } else if (vt != napi_function) {
            IAM_LOGE("callback is not a function");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
    }
    std::lock_guard<std::mutex> lock(manager->mutex_);
    if (clearAll) {
        for (const auto &cb : manager->callbacks_) {
            UserAuthClient::GetInstance().UnregisterUserRecognitionEventListener(cb);
        }
        manager->callbacks_.clear();
    } else {
        auto it = manager->FindCallback(env, argv[0]);
        if (it != manager->callbacks_.end()) {
            UserAuthClient::GetInstance().UnregisterUserRecognitionEventListener(*it);
            manager->callbacks_.erase(it);
        }
    }
    return UserAuthResultCode::SUCCESS;
}

napi_value UserRecognitionManagerNapi::Off(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthApiEventReporter reporter("OffUserRecognitionChange");
    UserAuthResultCode code = OffInternal(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
        reporter.ReportFailed(code);
        return nullptr;
    }
    reporter.ReportSuccess();
    return nullptr;
}

napi_value UserRecognitionStatusConstructor(napi_env env)
{
    napi_value status = nullptr;
    napi_value uncertain = nullptr;
    napi_value match = nullptr;
    napi_value mismatch = nullptr;
    NAPI_CALL(env, napi_create_object(env, &status));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserRecognitionStatus::UNCERTAIN), &uncertain));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserRecognitionStatus::MATCH), &match));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserRecognitionStatus::MISMATCH), &mismatch));
    NAPI_CALL(env, napi_set_named_property(env, status, "UNCERTAIN", uncertain));
    NAPI_CALL(env, napi_set_named_property(env, status, "MATCH", match));
    NAPI_CALL(env, napi_set_named_property(env, status, "MISMATCH", mismatch));
    return status;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

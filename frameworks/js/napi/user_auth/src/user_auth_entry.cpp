/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "iam_logger.h"

#include "auth_instance_v9.h"
#include "nlohmann/json.hpp"
#include "user_auth_api_event_reporter.h"
#include "user_auth_helper.h"
#include "user_auth_impl.h"
#include "user_auth_instance_v10.h"
#include "user_auth_widget_mgr_v10.h"
#include "user_auth_client_impl.h"

#define LOG_FILE_ID LOG_FILE_USER_AUTH_ENTRY
#define LOG_TAG "USER_AUTH_NAPI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const std::string NOTICE_WIDGET_CTXID = "widgetContextId";
const std::string NOTICE_EVENT_TYPE = "event";
const std::string NOTICE_VERSION = "version";
const std::string NOTICE_PAYLOAD = "payload";
const std::string NOTICE_PAYLOAD_TYPE = "type";
const std::string SUPPORT_NOTICE_VERSION = "1";

napi_value UserAuthServiceConstructor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    return thisVar;
}

napi_value GetVersion(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    return UserAuthImpl::GetVersion(env, info);
}

napi_value GetAvailableStatus(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    return UserAuthImpl::GetAvailableStatus(env, info);
}

napi_value GetEnrolledState(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    return UserAuthImpl::GetEnrolledState(env, info);
}

napi_value GetAvailableStatusV9(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthResultCode result = AuthInstanceV9::GetAvailableStatus(env, info);
    if (result != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("fail");
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, result));
    }
    return nullptr;
}

napi_status UnwrapAuthInstanceV9(napi_env env, napi_callback_info info, AuthInstanceV9 **authInstanceV9)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {nullptr};
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail");
        return ret;
    }
    ret = napi_unwrap(env, thisVar, reinterpret_cast<void **>(authInstanceV9));
    if (ret != napi_ok) {
        IAM_LOGE("napi_unwrap fail");
        return ret;
    }
    if (*authInstanceV9 == nullptr) {
        IAM_LOGE("authInstanceV9 is null");
        return napi_generic_failure;
    }
    return ret;
}

napi_value AuthInstanceV9Constructor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::unique_ptr<AuthInstanceV9> authInstanceV9 {new (std::nothrow) AuthInstanceV9(env)};
    if (authInstanceV9 == nullptr) {
        IAM_LOGE("authInstanceV9 is nullptr");
        return nullptr;
    }

    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env, napi_wrap(env, thisVar, authInstanceV9.get(),
        [](napi_env env, void *data, void *hint) {
            AuthInstanceV9 *authInstanceV9 = static_cast<AuthInstanceV9 *>(data);
            if (authInstanceV9 != nullptr) {
                delete authInstanceV9;
            }
        },
        nullptr, nullptr));
    authInstanceV9.release();
    return thisVar;
}

napi_value On(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AuthInstanceV9 *authInstance;
    napi_status ret = UnwrapAuthInstanceV9(env, info, &authInstance);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthInstanceV9 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = authInstance->On(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("On fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
    }
    return nullptr;
}

napi_value Off(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AuthInstanceV9 *authInstance;
    napi_status ret = UnwrapAuthInstanceV9(env, info, &authInstance);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthInstanceV9 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = authInstance->Off(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("Off fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
    }
    return nullptr;
}

napi_value Start(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AuthInstanceV9 *authInstance;
    napi_status ret = UnwrapAuthInstanceV9(env, info, &authInstance);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthInstanceV9 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = authInstance->Start(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("Start fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
    }
    return nullptr;
}

napi_value Cancel(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AuthInstanceV9 *authInstance;
    napi_status ret = UnwrapAuthInstanceV9(env, info, &authInstance);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthInstanceV9 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = authInstance->Cancel(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("Cancel fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
    }
    return nullptr;
}

napi_value AuthInstanceV9Class(napi_env env)
{
    napi_value result = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("on", UserAuth::On),
        DECLARE_NAPI_FUNCTION("off", UserAuth::Off),
        DECLARE_NAPI_FUNCTION("start", UserAuth::Start),
        DECLARE_NAPI_FUNCTION("cancel", UserAuth::Cancel),
    };
    NAPI_CALL(env, napi_define_class(env, "AuthInstace", NAPI_AUTO_LENGTH, AuthInstanceV9Constructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &result));
    return result;
}

napi_value GetAuthInstanceV9(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value authInstanceV9;
    napi_status ret = napi_new_instance(env, AuthInstanceV9Class(env), 0, nullptr, &authInstanceV9);
    if (ret != napi_ok) {
        IAM_LOGE("napi_new_instance fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    AuthInstanceV9 *authInstance;
    ret = napi_unwrap(env, authInstanceV9, reinterpret_cast<void **>(&authInstance));
    if (ret != napi_ok) {
        IAM_LOGE("napi_unwrap fail");
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    if (authInstance == nullptr) {
        IAM_LOGE("authInstanceV9 is null");
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = authInstance->Init(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("Init fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
        return nullptr;
    }
    return authInstanceV9;
}

napi_status UnwrapAuthInstanceV10(napi_env env, napi_callback_info info, UserAuthInstanceV10 **authInstanceV10)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {nullptr};
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail");
        return ret;
    }
    ret = napi_unwrap(env, thisVar, reinterpret_cast<void **>(authInstanceV10));
    if (ret != napi_ok) {
        IAM_LOGE("napi_unwrap fail");
        return ret;
    }
    if (*authInstanceV10 == nullptr) {
        IAM_LOGE("authInstanceV10 is null");
        return napi_generic_failure;
    }
    return ret;
}

napi_value OnV10(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthInstanceV10 *authInstance = nullptr;
    napi_status ret = UnwrapAuthInstanceV10(env, info, &authInstance);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthInstanceV10 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = authInstance->On(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("On fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
    }
    return nullptr;
}

napi_value OffV10(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthInstanceV10 *authInstance = nullptr;
    napi_status ret = UnwrapAuthInstanceV10(env, info, &authInstance);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthInstanceV10 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = authInstance->Off(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("Off fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
    }
    return nullptr;
}

napi_value StartV10(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthApiEventReporter reporter("UserAuthInstance::start");
    UserAuthInstanceV10 *authInstance = nullptr;
    napi_status ret = UnwrapAuthInstanceV10(env, info, &authInstance);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthInstanceV10 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        reporter.ReportFailed(UserAuthResultCode::GENERAL_ERROR);
        return nullptr;
    }
    UserAuthResultCode code = authInstance->Start(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("Start fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
        reporter.ReportFailed(code);
        return nullptr;
    }
    reporter.ReportSuccess();
    return nullptr;
}

napi_value CancelV10(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthApiEventReporter reporter("UserAuthInstance::cancel");
    UserAuthInstanceV10 *authInstance = nullptr;
    napi_status ret = UnwrapAuthInstanceV10(env, info, &authInstance);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthInstanceV10 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        reporter.ReportFailed(UserAuthResultCode::GENERAL_ERROR);
        return nullptr;
    }
    UserAuthResultCode code = authInstance->Cancel(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("Cancel fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
        reporter.ReportFailed(code);
        return nullptr;
    }
    reporter.ReportSuccess();
    return nullptr;
}

napi_value UserAuthInstanceV10Constructor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::unique_ptr<UserAuthInstanceV10> userAuthInstanceV10 {new (std::nothrow) UserAuthInstanceV10(env)};
    if (userAuthInstanceV10 == nullptr) {
        IAM_LOGE("userAuthInstanceV10 is nullptr");
        return nullptr;
    }

    napi_value thisVar = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env, napi_wrap(env, thisVar, userAuthInstanceV10.get(),
        [](napi_env env, void *data, void *hint) {
            UserAuthInstanceV10 *userAuthInstanceV10 = static_cast<UserAuthInstanceV10 *>(data);
            if (userAuthInstanceV10 != nullptr) {
                delete userAuthInstanceV10;
            }
        },
        nullptr, nullptr));
    userAuthInstanceV10.release();
    return thisVar;
}

napi_value UserAuthInstanceV10Class(napi_env env)
{
    napi_value result = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("on", UserAuth::OnV10),
        DECLARE_NAPI_FUNCTION("off", UserAuth::OffV10),
        DECLARE_NAPI_FUNCTION("start", UserAuth::StartV10),
        DECLARE_NAPI_FUNCTION("cancel", UserAuth::CancelV10),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuthInstance", NAPI_AUTO_LENGTH, UserAuthInstanceV10Constructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &result));
    return result;
}

napi_status UnwrapAuthWidgetMgrV10(napi_env env, napi_callback_info info, UserAuthWidgetMgr **authWidgetMgrV10)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {nullptr};
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail");
        return ret;
    }
    ret = napi_unwrap(env, thisVar, reinterpret_cast<void **>(authWidgetMgrV10));
    if (ret != napi_ok) {
        IAM_LOGE("napi_unwrap fail");
        return ret;
    }
    if (*authWidgetMgrV10 == nullptr) {
        IAM_LOGE("authWidgetMgr is null");
        return napi_generic_failure;
    }
    return ret;
}

napi_value WidgetOn(napi_env env, napi_callback_info info)
{
    IAM_LOGI("widgetOn");
    UserAuthWidgetMgr *authWidgetMgr = nullptr;
    napi_status ret = UnwrapAuthWidgetMgrV10(env, info, &authWidgetMgr);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthWidgetMgrV10 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = authWidgetMgr->On(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("widgetOn fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
    }
    return nullptr;
}

napi_value WidgetOff(napi_env env, napi_callback_info info)
{
    IAM_LOGI("widgetOff");
    UserAuthWidgetMgr *authWidgetMgr = nullptr;
    napi_status ret = UnwrapAuthWidgetMgrV10(env, info, &authWidgetMgr);
    if (ret != napi_ok) {
        IAM_LOGE("UnwrapAuthWidgetMgrV10 fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = authWidgetMgr->Off(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("widgetOff fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
    }
    return nullptr;
}

static bool VerifyNoticeParam(const std::string &eventData)
{
    auto json = nlohmann::json::parse(eventData.c_str(), nullptr, false);
    if (json.is_null() || json.is_discarded()) {
        IAM_LOGE("Notice data is invalid json object");
        return false;
    }

    if (json.find(NOTICE_EVENT_TYPE) == json.end() || !json[NOTICE_EVENT_TYPE].is_string()) {
        IAM_LOGE("Invalid event type exist in notice data");
        return false;
    }

    if (json.find(NOTICE_PAYLOAD) == json.end() ||
        json[NOTICE_PAYLOAD].find(NOTICE_PAYLOAD_TYPE) == json[NOTICE_PAYLOAD].end() ||
        !json[NOTICE_PAYLOAD][NOTICE_PAYLOAD_TYPE].is_array()) {
        IAM_LOGE("Invalid payload exist in notice data");
        return false;
    }
    IAM_LOGD("valid notice parameter");
    return true;
}

napi_value ResultOfSendNotice(napi_env env, UserAuthResultCode errCode)
{
    napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, errCode));
    return nullptr;
}

napi_value SendNotice(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start SendNotice");
    UserAuthResultCode errCode = UserAuthResultCode::SUCCESS;

    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return ResultOfSendNotice(env, UserAuthResultCode::GENERAL_ERROR);
    }
    if (argc != ARGS_TWO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        std::string msgStr = "Parameter error. The number of parameters should be 2";
        napi_throw(env, UserAuthNapiHelper::GenerateErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }

    NoticeType noticeType = NoticeType::WIDGET_NOTICE;
    int32_t noticeType_value = 0;
    ret = UserAuthNapiHelper::GetInt32Value(env, argv[PARAM0], noticeType_value);
    if (ret != napi_ok) {
        IAM_LOGE("GetStrValue fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"noticeType\" must be NoticeType.";
        napi_throw(env, UserAuthNapiHelper::GenerateErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }

    if (noticeType_value != WIDGET_NOTICE) {
        std::string msgStr = "Parameter error. The value of \"noticeType\" must be NoticeType.WIDGET_NOTICE.";
        napi_throw(env, UserAuthNapiHelper::GenerateErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }

    std::string eventData = UserAuthNapiHelper::GetStringFromValueUtf8(env, argv[PARAM1]);
    IAM_LOGI("recv SendNotice type:%{public}d, eventData:%{public}s", noticeType_value, eventData.c_str());
    if (!VerifyNoticeParam(eventData)) {
        IAM_LOGE("Invalid notice parameter");
        std::string msgStr = "Parameter error. The value of \"eventData\" for WIDGET_NOTICE must be json string.";
        napi_throw(env, UserAuthNapiHelper::GenerateErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }

    int32_t result = UserAuthClientImpl::Instance().Notice(noticeType, eventData);
    if (result != ResultCode::SUCCESS) {
        errCode = UserAuthResultCode(UserAuthHelper::GetResultCodeV10(result));
        IAM_LOGE("SendNotice fail. result: %{public}d, errCode: %{public}d", result, errCode);
        return ResultOfSendNotice(env, errCode);
    }
    IAM_LOGD("end SendNotice");
    return nullptr;
}

napi_value UserAuthWidgetMgrV10Constructor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::unique_ptr<UserAuthWidgetMgr> userAuthWidgetMgrV10 {new (std::nothrow) UserAuthWidgetMgr(env)};
    if (userAuthWidgetMgrV10 == nullptr) {
        IAM_LOGE("userAuthWidgetMgrV10 is nullptr");
        return nullptr;
    }

    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env, napi_wrap(env, thisVar, userAuthWidgetMgrV10.get(),
        [](napi_env env, void *data, void *hint) {
            UserAuthWidgetMgr *userAuthWidgetMgrV10 = static_cast<UserAuthWidgetMgr *>(data);
            if (userAuthWidgetMgrV10 != nullptr) {
                delete userAuthWidgetMgrV10;
            }
        },
        nullptr, nullptr));
    userAuthWidgetMgrV10.release();
    return thisVar;
}

napi_value UserAuthWidgetMgrV10Class(napi_env env)
{
    napi_value result = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("on", UserAuth::WidgetOn),
        DECLARE_NAPI_FUNCTION("off", UserAuth::WidgetOff),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuthWidgetMgr", NAPI_AUTO_LENGTH, UserAuthWidgetMgrV10Constructor,
        nullptr, sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &result));
    return result;
}

napi_value GetUserAuthInstanceV10(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    UserAuthApiEventReporter reporter("getUserAuthInstance");
    napi_value userAuthInstanceV10;
    napi_status ret = napi_new_instance(env, UserAuthInstanceV10Class(env), 0, nullptr, &userAuthInstanceV10);
    if (ret != napi_ok) {
        IAM_LOGE("napi_new_instance fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        reporter.ReportFailed(UserAuthResultCode::GENERAL_ERROR);
        return nullptr;
    }
    UserAuthInstanceV10 *userAuthInstance = nullptr;
    ret = napi_unwrap(env, userAuthInstanceV10, reinterpret_cast<void **>(&userAuthInstance));
    if (ret != napi_ok) {
        IAM_LOGE("napi_unwrap fail");
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        reporter.ReportFailed(UserAuthResultCode::GENERAL_ERROR);
        return nullptr;
    }
    if (userAuthInstance == nullptr) {
        IAM_LOGE("userAuthInstanceV10 is null");
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        reporter.ReportFailed(UserAuthResultCode::GENERAL_ERROR);
        return nullptr;
    }
    UserAuthResultCode code = userAuthInstance->Init(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("Init fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
        reporter.ReportFailed(code);
        return nullptr;
    }

    IAM_LOGE("GetUserAuthInstanceV10 SUCCESS");
    reporter.ReportSuccess();
    return userAuthInstanceV10;
}

napi_value GetUserAuthWidgetMgrV10(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value userAuthWidgetMgrV10;
    napi_status ret = napi_new_instance(env, UserAuthWidgetMgrV10Class(env), 0, nullptr, &userAuthWidgetMgrV10);
    if (ret != napi_ok) {
        IAM_LOGE("napi_new_instance fail:%{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthWidgetMgr *userAuthWidgetMgr = nullptr;
    ret = napi_unwrap(env, userAuthWidgetMgrV10, reinterpret_cast<void **>(&userAuthWidgetMgr));
    if (ret != napi_ok) {
        IAM_LOGE("napi_unwrap fail");
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    if (userAuthWidgetMgr == nullptr) {
        IAM_LOGE("userAuthWidgetMgr is null");
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    UserAuthResultCode code = userAuthWidgetMgr->Init(env, info);
    if (code != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("Init fail:%{public}d", static_cast<int32_t>(code));
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, code));
        return nullptr;
    }
    IAM_LOGD("end");
    return userAuthWidgetMgrV10;
}

napi_value Auth(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    return UserAuthImpl::Auth(env, info);
}

napi_value Execute(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    return UserAuthImpl::Execute(env, info);
}

napi_value CancelAuth(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    return UserAuthImpl::CancelAuth(env, info);
}

napi_value QueryReusableAuthResult(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    return UserAuthImpl::QueryReusableAuthResult(env, info);
}

napi_value GetAuthLockState(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    return UserAuthImpl::GetAuthLockState(env, info);
}

napi_value AuthTrustLevelConstructor(napi_env env)
{
    napi_value authTrustLevel = nullptr;
    napi_value atl1 = nullptr;
    napi_value atl2 = nullptr;
    napi_value atl3 = nullptr;
    napi_value atl4 = nullptr;
    NAPI_CALL(env, napi_create_object(env, &authTrustLevel));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL1), &atl1));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL2), &atl2));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL3), &atl3));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL4), &atl4));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL1", atl1));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL2", atl2));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL3", atl3));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL4", atl4));
    return authTrustLevel;
}

napi_value ResultCodeConstructor(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_value success = nullptr;
    napi_value fail = nullptr;
    napi_value generalError = nullptr;
    napi_value canceled = nullptr;
    napi_value timeout = nullptr;
    napi_value typeNotSupport = nullptr;
    napi_value trustLevelNotSupport = nullptr;
    napi_value busy = nullptr;
    napi_value invalidParameters = nullptr;
    napi_value locked = nullptr;
    napi_value notEnrolled = nullptr;
    napi_value canceledFromWidget = nullptr;
    NAPI_CALL(env, napi_create_object(env, &resultCode));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::SUCCESS, &success));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::FAIL, &fail));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::GENERAL_ERROR, &generalError));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::CANCELED, &canceled));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::TIMEOUT, &timeout));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::TYPE_NOT_SUPPORT, &typeNotSupport));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::TRUST_LEVEL_NOT_SUPPORT, &trustLevelNotSupport));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::BUSY, &busy));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::INVALID_PARAMETERS, &invalidParameters));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::LOCKED, &locked));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::NOT_ENROLLED, &notEnrolled));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::CANCELED_FROM_WIDGET, &canceledFromWidget));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "SUCCESS", success));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "FAIL", fail));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "GENERAL_ERROR", generalError));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CANCELED", canceled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TIMEOUT", timeout));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TYPE_NOT_SUPPORT", typeNotSupport));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TRUST_LEVEL_NOT_SUPPORT", trustLevelNotSupport));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "BUSY", busy));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "INVALID_PARAMETERS", invalidParameters));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "LOCKED", locked));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "NOT_ENROLLED", notEnrolled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CANCELED_FROM_WIDGET", canceledFromWidget));
    return resultCode;
}

napi_value UserAuthResultCodeExtConstructor(napi_env env, napi_value resultCode)
{
    napi_value pinExpired = nullptr;
    napi_value authTokenCheckFailed = nullptr;
    napi_value authTokenExpired = nullptr;
    napi_value reuseAuthResultFailed = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::PIN_EXPIRED), &pinExpired));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(UserAuthResultCode::AUTH_TOKEN_CHECK_FAILED), &authTokenCheckFailed));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(UserAuthResultCode::AUTH_TOKEN_EXPIRED), &authTokenExpired));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(UserAuthResultCode::REUSE_AUTH_RESULT_FAILED), &reuseAuthResultFailed));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "PIN_EXPIRED", pinExpired));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTH_TOKEN_CHECK_FAILED", authTokenCheckFailed));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "AUTH_TOKEN_EXPIRED", authTokenExpired));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "REUSE_AUTH_RESULT_FAILED", reuseAuthResultFailed));
    return resultCode;
}

napi_value UserAuthResultCodeConstructor(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_value success = nullptr;
    napi_value fail = nullptr;
    napi_value generalError = nullptr;
    napi_value canceled = nullptr;
    napi_value timeout = nullptr;
    napi_value typeNotSupport = nullptr;
    napi_value trustLevelNotSupport = nullptr;
    napi_value busy = nullptr;
    napi_value paramVerifiedFailed = nullptr;
    napi_value locked = nullptr;
    napi_value notEnrolled = nullptr;
    napi_value canceledFromWidget = nullptr;
    NAPI_CALL(env, napi_create_object(env, &resultCode));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::SUCCESS), &success));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::FAIL), &fail));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR), &generalError));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::CANCELED), &canceled));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::TIMEOUT), &timeout));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(UserAuthResultCode::TYPE_NOT_SUPPORT), &typeNotSupport));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT), &trustLevelNotSupport));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::BUSY), &busy));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(UserAuthResultCode::PARAM_VERIFIED_FAILED), &paramVerifiedFailed));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::LOCKED), &locked));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::NOT_ENROLLED), &notEnrolled));
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(UserAuthResultCode::CANCELED_FROM_WIDGET), &canceledFromWidget));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "SUCCESS", success));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "FAIL", fail));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "GENERAL_ERROR", generalError));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CANCELED", canceled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TIMEOUT", timeout));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TYPE_NOT_SUPPORT", typeNotSupport));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TRUST_LEVEL_NOT_SUPPORT", trustLevelNotSupport));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "INVALID_PARAMETERS", paramVerifiedFailed));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "BUSY", busy));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "LOCKED", locked));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "NOT_ENROLLED", notEnrolled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CANCELED_FROM_WIDGET", canceledFromWidget));
    return UserAuthResultCodeExtConstructor(env, resultCode);
}

napi_value AuthenticationResultConstructor(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_value noSupport = nullptr;
    napi_value success = nullptr;
    napi_value compareFailure = nullptr;
    napi_value canceled = nullptr;
    napi_value timeout = nullptr;
    napi_value cameraFail = nullptr;
    napi_value busy = nullptr;
    napi_value invalidParameters = nullptr;
    napi_value locked = nullptr;
    napi_value notEnrolled = nullptr;
    napi_value generalError = nullptr;
    NAPI_CALL(env, napi_create_object(env, &resultCode));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::NO_SUPPORT), &noSupport));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::SUCCESS), &success));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::COMPARE_FAILURE),
        &compareFailure));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::CANCELED), &canceled));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::TIMEOUT), &timeout));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::CAMERA_FAIL), &cameraFail));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::BUSY), &busy));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::INVALID_PARAMETERS),
        &invalidParameters));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::LOCKED), &locked));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::NOT_ENROLLED), &notEnrolled));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::GENERAL_ERROR), &generalError));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "NO_SUPPORT", noSupport));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "SUCCESS", success));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "COMPARE_FAILURE", compareFailure));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CANCELED", canceled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TIMEOUT", timeout));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CAMERA_FAIL", cameraFail));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "BUSY", busy));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "INVALID_PARAMETERS", invalidParameters));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "LOCKED", locked));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "NOT_ENROLLED", notEnrolled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "GENERAL_ERROR", generalError));
    return resultCode;
}

napi_value FaceTipsCodeConstructor(napi_env env)
{
    napi_value faceTipsCode = nullptr;
    napi_value faceAuthTipTooBright = nullptr;
    napi_value faceAuthTipTooDark = nullptr;
    napi_value faceAuthTipTooClose = nullptr;
    napi_value faceAuthTipTooFar = nullptr;
    napi_value faceAuthTipTooHigh = nullptr;
    napi_value faceAuthTipTooLow = nullptr;
    napi_value faceAuthTipTooRight = nullptr;
    napi_value faceAuthTipTooLeft = nullptr;
    napi_value faceAuthTipTooMuchMotion = nullptr;
    napi_value faceAuthTipPoorGaze = nullptr;
    napi_value faceAuthTipNotDetected = nullptr;
    NAPI_CALL(env, napi_create_object(env, &faceTipsCode));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_BRIGHT, &faceAuthTipTooBright));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_DARK, &faceAuthTipTooDark));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_CLOSE, &faceAuthTipTooClose));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_FAR, &faceAuthTipTooFar));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_HIGH, &faceAuthTipTooHigh));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_LOW, &faceAuthTipTooLow));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_RIGHT, &faceAuthTipTooRight));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_LEFT, &faceAuthTipTooLeft));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_MUCH_MOTION, &faceAuthTipTooMuchMotion));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_POOR_GAZE, &faceAuthTipPoorGaze));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_NOT_DETECTED, &faceAuthTipNotDetected));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_BRIGHT", faceAuthTipTooBright));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_DARK", faceAuthTipTooDark));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_CLOSE", faceAuthTipTooClose));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_FAR", faceAuthTipTooFar));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_HIGH", faceAuthTipTooHigh));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_LOW", faceAuthTipTooLow));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_RIGHT", faceAuthTipTooRight));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_LEFT", faceAuthTipTooLeft));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode,
        "FACE_AUTH_TIP_TOO_MUCH_MOTION", faceAuthTipTooMuchMotion));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_POOR_GAZE", faceAuthTipPoorGaze));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_NOT_DETECTED", faceAuthTipNotDetected));
    return faceTipsCode;
}

napi_value FingerprintTipsConstructorForKits(napi_env env)
{
    napi_value fingerprintTips = nullptr;
    napi_value fingerprintTipGood = nullptr;
    napi_value fingerprintTipImagerDirty = nullptr;
    napi_value fingerprintTipInsufficient = nullptr;
    napi_value fingerprintTipPartial = nullptr;
    napi_value fingerprintTipTooFast = nullptr;
    napi_value fingerprintTipTooSlow = nullptr;
    NAPI_CALL(env, napi_create_object(env, &fingerprintTips));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_GOOD, &fingerprintTipGood));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_IMAGER_DIRTY,
        &fingerprintTipImagerDirty));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_INSUFFICIENT,
        &fingerprintTipInsufficient));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_PARTIAL, &fingerprintTipPartial));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_TOO_FAST, &fingerprintTipTooFast));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_TOO_SLOW, &fingerprintTipTooSlow));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips, "FINGERPRINT_AUTH_TIP_GOOD", fingerprintTipGood));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_DIRTY", fingerprintTipImagerDirty));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_INSUFFICIENT", fingerprintTipInsufficient));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_PARTIAL", fingerprintTipPartial));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_TOO_FAST", fingerprintTipTooFast));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_TOO_SLOW", fingerprintTipTooSlow));
    return fingerprintTips;
}

napi_value UserAuthTypeConstructor(napi_env env)
{
    napi_value userAuthType = nullptr;
    napi_value pin = nullptr;
    napi_value face = nullptr;
    napi_value fingerprint = nullptr;
    napi_value privatePin = nullptr;
    napi_value companionDevice = nullptr;
    NAPI_CALL(env, napi_create_object(env, &userAuthType));
    NAPI_CALL(env, napi_create_int32(env, AuthType::PIN, &pin));
    NAPI_CALL(env, napi_create_int32(env, AuthType::FACE, &face));
    NAPI_CALL(env, napi_create_int32(env, AuthType::FINGERPRINT, &fingerprint));
    NAPI_CALL(env, napi_create_int32(env, AuthType::PRIVATE_PIN, &privatePin));
    NAPI_CALL(env, napi_create_int32(env, AuthType::COMPANION_DEVICE, &companionDevice));
    NAPI_CALL(env, napi_set_named_property(env, userAuthType, "PIN", pin));
    NAPI_CALL(env, napi_set_named_property(env, userAuthType, "FACE", face));
    NAPI_CALL(env, napi_set_named_property(env, userAuthType, "FINGERPRINT", fingerprint));
    NAPI_CALL(env, napi_set_named_property(env, userAuthType, "PRIVATE_PIN", privatePin));
    NAPI_CALL(env, napi_set_named_property(env, userAuthType, "COMPANION_DEVICE", companionDevice));
    return userAuthType;
}

napi_value NoticeTypeConstructor(napi_env env)
{
    napi_value noticeType = nullptr;
    napi_value widget_notice = nullptr;
    NAPI_CALL(env, napi_create_object(env, &noticeType));
    NAPI_CALL(env, napi_create_int32(env, NoticeType::WIDGET_NOTICE, &widget_notice));
    NAPI_CALL(env, napi_set_named_property(env, noticeType, "WIDGET_NOTICE", widget_notice));
    return noticeType;
}

napi_value WindowModeTypeConstructor(napi_env env)
{
    napi_value windowModeType = nullptr;
    napi_value dialog_box = nullptr;
    napi_value fullscreen = nullptr;
    napi_value none_interruption_dialog_box = nullptr;
    NAPI_CALL(env, napi_create_object(env, &windowModeType));
    NAPI_CALL(env, napi_create_int32(env, WindowModeType::DIALOG_BOX, &dialog_box));
    NAPI_CALL(env, napi_create_int32(env, WindowModeType::FULLSCREEN, &fullscreen));
    NAPI_CALL(env, napi_create_int32(env, WindowModeType::NONE_INTERRUPTION_DIALOG_BOX,
        &none_interruption_dialog_box));
    NAPI_CALL(env, napi_set_named_property(env, windowModeType, "DIALOG_BOX", dialog_box));
    NAPI_CALL(env, napi_set_named_property(env, windowModeType, "FULLSCREEN", fullscreen));
    NAPI_CALL(env, napi_set_named_property(env, windowModeType, "NONE_INTERRUPTION_DIALOG_BOX",
        none_interruption_dialog_box));
    return windowModeType;
}

napi_value ReuseModeConstructor(napi_env env)
{
    napi_value reuseMode = nullptr;
    napi_value auth_type_relevant = nullptr;
    napi_value auth_type_irrelevant = nullptr;
    napi_value caller_irrelevant_auth_type_relevant = nullptr;
    napi_value caller_irrelevant_auth_type_irrelevant = nullptr;
    NAPI_CALL(env, napi_create_object(env, &reuseMode));
    NAPI_CALL(env, napi_create_int32(env, ReuseMode::AUTH_TYPE_RELEVANT, &auth_type_relevant));
    NAPI_CALL(env, napi_create_int32(env, ReuseMode::AUTH_TYPE_IRRELEVANT, &auth_type_irrelevant));
    NAPI_CALL(env, napi_create_int32(
        env, ReuseMode::CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT, &caller_irrelevant_auth_type_relevant));
    NAPI_CALL(env, napi_create_int32(
        env, ReuseMode::CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT, &caller_irrelevant_auth_type_irrelevant));
    NAPI_CALL(env, napi_set_named_property(env, reuseMode, "AUTH_TYPE_RELEVANT", auth_type_relevant));
    NAPI_CALL(env, napi_set_named_property(env, reuseMode, "AUTH_TYPE_IRRELEVANT", auth_type_irrelevant));
    NAPI_CALL(env, napi_set_named_property(
        env, reuseMode, "CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT", caller_irrelevant_auth_type_relevant));
    NAPI_CALL(env, napi_set_named_property(
        env, reuseMode, "CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT", caller_irrelevant_auth_type_irrelevant));
    return reuseMode;
}

napi_value UserAuthTipCodeConstructor(napi_env env)
{
    napi_value userAuthTipCode = nullptr;
    napi_value compareFailure = nullptr;
    napi_value timeout = nullptr;
    napi_value temporaryLocked = nullptr;
    napi_value permanentLocked = nullptr;
    napi_value widgetLoaded = nullptr;
    napi_value widgetReleased = nullptr;
    napi_value cmpFailWithFrozen = nullptr;
    NAPI_CALL(env, napi_create_object(env, &userAuthTipCode));
    NAPI_CALL(env, napi_create_int32(env, UserAuthTipCode::TIP_CODE_FAIL, &compareFailure));
    NAPI_CALL(env, napi_create_int32(env, UserAuthTipCode::TIP_CODE_TIMEOUT, &timeout));
    NAPI_CALL(env, napi_create_int32(env, UserAuthTipCode::TIP_CODE_TEMPORARILY_LOCKED, &temporaryLocked));
    NAPI_CALL(env, napi_create_int32(env, UserAuthTipCode::TIP_CODE_PERMANENTLY_LOCKED, &permanentLocked));
    NAPI_CALL(env, napi_create_int32(env, UserAuthTipCode::TIP_CODE_WIDGET_LOADED, &widgetLoaded));
    NAPI_CALL(env, napi_create_int32(env, UserAuthTipCode::TIP_CODE_WIDGET_RELEASED, &widgetReleased));
    NAPI_CALL(env, napi_create_int32(env, UserAuthTipCode::TIP_CODE_COMPARE_FAIL_WITH_FROZEN, &cmpFailWithFrozen));
    NAPI_CALL(env, napi_set_named_property(env, userAuthTipCode, "COMPARE_FAILURE", compareFailure));
    NAPI_CALL(env, napi_set_named_property(env, userAuthTipCode, "TIMEOUT", timeout));
    NAPI_CALL(env, napi_set_named_property(env, userAuthTipCode, "TEMPORARILY_LOCKED", temporaryLocked));
    NAPI_CALL(env, napi_set_named_property(env, userAuthTipCode, "PERMANENTLY_LOCKED", permanentLocked));
    NAPI_CALL(env, napi_set_named_property(env, userAuthTipCode, "WIDGET_LOADED", widgetLoaded));
    NAPI_CALL(env, napi_set_named_property(env, userAuthTipCode, "WIDGET_RELEASED", widgetReleased));
    NAPI_CALL(env, napi_set_named_property(env, userAuthTipCode, "COMPARE_FAILURE_WITH_FROZEN", cmpFailWithFrozen));
    return userAuthTipCode;
}

napi_value ConstantConstructor(napi_env env)
{
    napi_value staticValue = nullptr;
    const int32_t MAX_ALLOWABLE_REUSE_DURATION = 300000;
    NAPI_CALL(env, napi_create_int32(env, MAX_ALLOWABLE_REUSE_DURATION, &staticValue));
    return staticValue;
}

napi_value LockoutDurationConstantConstructor(napi_env env)
{
    napi_value staticValue = nullptr;
    const int32_t PERMANENT_LOCKOUT_DURATION = 0x7fffffff;
    NAPI_CALL(env, napi_create_int32(env, PERMANENT_LOCKOUT_DURATION, &staticValue));
    return staticValue;
}

napi_value GetCtor(napi_env env)
{
    IAM_LOGI("start");
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("getVersion", UserAuth::GetVersion),
        DECLARE_NAPI_FUNCTION("getAvailableStatus", UserAuth::GetAvailableStatus),
        DECLARE_NAPI_FUNCTION("auth", UserAuth::Auth),
        DECLARE_NAPI_FUNCTION("cancelAuth", UserAuth::CancelAuth),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuth", NAPI_AUTO_LENGTH, UserAuthServiceConstructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    return cons;
}

napi_value GetCtorForApi6(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("execute", UserAuth::Execute),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuth", NAPI_AUTO_LENGTH, UserAuthServiceConstructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    return cons;
}

napi_value ConstructorForApi6(napi_env env, napi_callback_info info)
{
    napi_value userAuthForApi6 = nullptr;
    NAPI_CALL(env, napi_new_instance(env, GetCtorForApi6(env), 0, nullptr, &userAuthForApi6));
    return userAuthForApi6;
}

napi_value UserAuthInit(napi_env env, napi_value exports)
{
    IAM_LOGI("start");
    napi_status status;
    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_FUNCTION("getAuthenticator", UserAuth::ConstructorForApi6),
        DECLARE_NAPI_FUNCTION("getAvailableStatus", UserAuth::GetAvailableStatusV9),
        DECLARE_NAPI_FUNCTION("getAuthInstance", UserAuth::GetAuthInstanceV9),
        DECLARE_NAPI_FUNCTION("getUserAuthInstance", UserAuth::GetUserAuthInstanceV10),
        DECLARE_NAPI_FUNCTION("getUserAuthWidgetMgr", UserAuth::GetUserAuthWidgetMgrV10),
        DECLARE_NAPI_FUNCTION("getEnrolledState", UserAuth::GetEnrolledState),
        DECLARE_NAPI_FUNCTION("sendNotice", UserAuth::SendNotice),
        DECLARE_NAPI_FUNCTION("queryReusableAuthResult", UserAuth::QueryReusableAuthResult),
        DECLARE_NAPI_FUNCTION("getAuthLockState", UserAuth::GetAuthLockState),
    };
    status = napi_define_properties(env, exports,
        sizeof(exportFuncs) / sizeof(napi_property_descriptor), exportFuncs);
    if (status != napi_ok) {
        IAM_LOGE("napi_define_properties failed");
        NAPI_CALL(env, status);
    }
    status = napi_set_named_property(env, exports, "UserAuth", GetCtor(env));
    if (status != napi_ok) {
        IAM_LOGE("napi_set_named_property failed");
        NAPI_CALL(env, status);
    }
    return exports;
}

napi_value ConstantsExport(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_STATIC_PROPERTY("MAX_ALLOWABLE_REUSE_DURATION", ConstantConstructor(env)),
        DECLARE_NAPI_STATIC_PROPERTY("PERMANENT_LOCKOUT_DURATION", LockoutDurationConstantConstructor(env)),
    };
    NAPI_CALL(env, napi_define_properties(env, exports,
        sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors));
    return exports;
}

napi_value EnumExport(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("AuthTrustLevel", AuthTrustLevelConstructor(env)),
        DECLARE_NAPI_PROPERTY("ResultCode", ResultCodeConstructor(env)),
        DECLARE_NAPI_PROPERTY("UserAuthResultCode", UserAuthResultCodeConstructor(env)),
        DECLARE_NAPI_PROPERTY("FingerprintTips", FingerprintTipsConstructorForKits(env)),
        DECLARE_NAPI_PROPERTY("UserAuthType", UserAuthTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("FaceTips", FaceTipsCodeConstructor(env)),
        DECLARE_NAPI_PROPERTY("AuthenticationResult", AuthenticationResultConstructor(env)),
        //add
        DECLARE_NAPI_PROPERTY("NoticeType", NoticeTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("WindowModeType", WindowModeTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("ReuseMode", ReuseModeConstructor(env)),
        DECLARE_NAPI_PROPERTY("UserAuthTipCode", UserAuthTipCodeConstructor(env)),
    };
    NAPI_CALL(env, napi_define_properties(env, exports,
        sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors));
    return ConstantsExport(env, exports);
}

napi_value ModuleInit(napi_env env, napi_value exports)
{
    napi_value val = UserAuthInit(env, exports);
    return EnumExport(env, val);
}
} // namespace

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module module = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = ModuleInit,
        .nm_modname = "userIAM.userAuth",
        .nm_priv = nullptr,
        .reserved = {}
    };
    napi_module_register(&module);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "user_auth_service_test.h"

#include <future>

#include "iam_common_defines.h"
#include "iam_ptr.h"

#include "executor_messenger_service.h"
#include "hdi_type_aliases.h"
#include "mock_event_listener.h"
#include "mock_context.h"
#include "mock_iuser_auth_interface.h"
#include "mock_ipc_common.h"
#include "mock_modal_callback.h"
#include "mock_user_access_ctrl_callback.h"
#include "mock_user_auth_callback.h"
#include "mock_user_auth_service.h"
#include "mock_user_recognition_callback.h"
#include "mock_resource_node.h"
#include "mock_widget_callback_interface.h"
#include "resource_node_pool.h"
#include "user_auth_service.h"
#include "user_auth_helper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {PIN, FACE, PRIVATE_PIN},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    const WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::NONE_INTERRUPTION_DIALOG_BOX,
    };
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {PIN, FACE, PRIVATE_PIN},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    const WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {PIN, FACE, PRIVATE_PIN},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);

    authParam.credentialIdList.resize(MAX_USER_CREDENTIAL_SIZE + 1);
    ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_004, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .userId = 200,
        .challenge = challenge,
        .authTypes = {PIN, FACE, PRIVATE_PIN},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    const WidgetParamInner widgetParam = {
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_002, TestSize.Level0)
{
    UserAuthService service;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    AuthParamInner authParam = {
        .challenge = {},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillOnce(Return(HDF_ERR_INVALID_PARAM));
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FINGERPRINT);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::FACE);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), false);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FINGERPRINT);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::PRIVATE_PIN);
    validAuthTypeList.push_back(AuthType::FACE);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FINGERPRINT);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::PRIVATE_PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice_001, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    int32_t ret = service.Notice(static_cast<int32_t>(NoticeType::WIDGET_NOTICE), "PIN");
    EXPECT_NE(ret, ResultCode::SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice_002, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    int32_t ret = service.Notice(static_cast<int32_t>(NoticeType::WIDGET_NOTICE), "PIN");
    EXPECT_EQ(ret, ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice_003, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    int32_t ret = service.Notice(static_cast<int32_t>(NoticeType::WIDGET_NOTICE), "PIN");
    EXPECT_EQ(ret, ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_001, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_002, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_003, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(2, testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_004, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_005, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = new MockIWidgetCallback();
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_006, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_001, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_003, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback),
        ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_004, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback),
        ResultCode::GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_005, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback),
        ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_001, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_002, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_003, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_004, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback), ResultCode::GENERAL_ERROR);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

// CheckUserRecognitionCapability: permission failure is reported via checkResult (IPC ret stays
// SUCCESS); with ACCESS_USER_PASSIVE_RECOGNITION granted and the default engine reporting no
// SUPPORT_USER_RECOGNITION capability the result is DEVICE_CAPABILITY_NOT_SUPPORT.
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckUserRecognitionCapability001, TestSize.Level0)
{
    UserAuthService service;
    int32_t checkResult = SUCCESS;
    EXPECT_EQ(service.CheckUserRecognitionCapability(checkResult), ResultCode::SUCCESS);
    EXPECT_EQ(checkResult, ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ACCESS_USER_PASSIVE_RECOGNITION_PERMISSION);
    checkResult = SUCCESS;
    EXPECT_EQ(service.CheckUserRecognitionCapability(checkResult), ResultCode::SUCCESS);
    EXPECT_EQ(checkResult, ResultCode::DEVICE_CAPABILITY_NOT_SUPPORT);
    IpcCommon::DeleteAllPermission();
}

// GetUserRecognitionResult mirrors CheckUserRecognitionCapability: permission failure lands in
// funcResult, and the absent engine capability yields DEVICE_CAPABILITY_NOT_SUPPORT.
HWTEST_F(UserAuthServiceTest, UserAuthServiceGetUserRecognitionResult001, TestSize.Level0)
{
    UserAuthService service;
    IpcUserRecognitionResult result;
    int32_t funcResult = SUCCESS;
    EXPECT_EQ(service.GetUserRecognitionResult(result, funcResult), ResultCode::SUCCESS);
    EXPECT_EQ(funcResult, ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ACCESS_USER_PASSIVE_RECOGNITION_PERMISSION);
    funcResult = SUCCESS;
    EXPECT_EQ(service.GetUserRecognitionResult(result, funcResult), ResultCode::SUCCESS);
    EXPECT_EQ(funcResult, ResultCode::DEVICE_CAPABILITY_NOT_SUPPORT);
    IpcCommon::DeleteAllPermission();
}

// Register/UnregisterUserRecognitionEventListener: nullptr listener is rejected before the
// permission check; both endpoints are gated by ACCESS_USER_PASSIVE_RECOGNITION, so the legacy
// ACCESS_BIOMETRIC alone still yields CHECK_PERMISSION_FAILED; adding
// ACCESS_USER_PASSIVE_RECOGNITION reaches the engine capability check, which reports
// DEVICE_CAPABILITY_NOT_SUPPORT by default.
HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterUserRecognitionEventListener001, TestSize.Level0)
{
    UserAuthService service;
    sptr<IUserRecognitionCallback> testCallback = nullptr;
    EXPECT_EQ(service.RegisterUserRecognitionEventListener(testCallback), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(service.UnregisterUserRecognitionEventListener(testCallback), ResultCode::INVALID_PARAMETERS);

    testCallback = new (std::nothrow) MockUserRecognitionCallback();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_EQ(service.RegisterUserRecognitionEventListener(testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    EXPECT_EQ(service.UnregisterUserRecognitionEventListener(testCallback), ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    EXPECT_EQ(service.RegisterUserRecognitionEventListener(testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    EXPECT_EQ(service.UnregisterUserRecognitionEventListener(testCallback), ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ACCESS_USER_PASSIVE_RECOGNITION_PERMISSION);
    EXPECT_EQ(service.RegisterUserRecognitionEventListener(testCallback),
        ResultCode::DEVICE_CAPABILITY_NOT_SUPPORT);
    EXPECT_EQ(service.UnregisterUserRecognitionEventListener(testCallback),
        ResultCode::DEVICE_CAPABILITY_NOT_SUPPORT);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam001, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.type = PIN_EXPIRED_PERIOD;
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);
    param.authTypes.push_back(PIN);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::SUCCESS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(*mockHdi, SetGlobalConfigParam)
        .WillByDefault(
            [](const HdiGlobalConfigParam &param) {
                return HDF_SUCCESS;
            }
        );
    EXPECT_EQ(service.SetGlobalConfigParam(param), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam002, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.type = ENABLE_STATUS;
    param.value.enableStatus = true;
    param.userIds.push_back(1);
    param.authTypes.push_back(PIN);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::SUCCESS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(*mockHdi, SetGlobalConfigParam)
        .WillByDefault(
            [](const HdiGlobalConfigParam &param) {
                return HDF_FAILURE;
            }
        );
    EXPECT_EQ(service.SetGlobalConfigParam(param), GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam003, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.type = PIN_EXPIRED_PERIOD;
    param.value.enableStatus = true;
    param.userIds.push_back(1);
    param.authTypes.push_back(ALL);
    param.authTypes.push_back(PIN);
    param.authTypes.push_back(FACE);
    param.authTypes.push_back(FINGERPRINT);
    param.authTypes.push_back(RECOVERY_KEY);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);
    param.authTypes.clear();
    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    testTokenIn.resize(1);
    uint64_t allowableDuration = 0;

    sptr<MockVerifyTokenCallback> testCallback(nullptr);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, VerifyAuthToken(_, _, _, _))
        .WillOnce([](const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
            HdiUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t> &rootSecret) {
            return HDF_SUCCESS;
        });

    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    uint64_t allowableDuration = 0;
    sptr<MockVerifyTokenCallback> testCallback(nullptr);
    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(2);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    EXPECT_EQ(service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface), INVALID_PARAMETERS);

    testTokenIn.resize(1);
    allowableDuration = 25 * 60 * 60 * 1000;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    testTokenIn.resize(1);
    uint64_t allowableDuration = 0;
    sptr<MockVerifyTokenCallback> testCallback(nullptr);
    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(2);
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);

    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    EXPECT_EQ(service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface), CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken004, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    testTokenIn.resize(1);
    uint64_t allowableDuration = 0;

    sptr<MockVerifyTokenCallback> testCallback(nullptr);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, VerifyAuthToken(_, _, _, _))
        .WillOnce([](const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
            HdiUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t> &rootSecret) {
            return HDF_FAILURE;
        });

    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    EXPECT_EQ(service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface), GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken005, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    testTokenIn.resize(1);
    uint64_t allowableDuration = 0;

    sptr<MockVerifyTokenCallback> testCallback(nullptr);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, VerifyAuthToken(_, _, _, _))
        .WillOnce([](const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
            HdiUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t> &rootSecret) {
            rootSecret.push_back(1);
            return HDF_SUCCESS;
        });

    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    EXPECT_EQ(service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAuthTokenAttrSchedule001, TestSize.Level0)
{
    UserAuthService service;
    EngUserAuthTokenPlain tokenPlain = {};
    tokenPlain.tokenSchedule = TokenSchedule {};
    tokenPlain.tokenSchedule->hasValidStartTime = true;
    tokenPlain.tokenSchedule->validStartTime = 1000;

    Attributes regularTokenAttr;
    EXPECT_TRUE(service.GetAuthTokenAttr(tokenPlain, {}, regularTokenAttr));
    TokenSchedule schedule = {};
    EXPECT_FALSE(UserAuthHelper::GetTokenScheduleAttr(regularTokenAttr, schedule));

    tokenPlain.tokenType = TOKEN_TYPE_SCHEDULED_AUTH;
    Attributes scheduledTokenAttr;
    EXPECT_TRUE(service.GetAuthTokenAttr(tokenPlain, {}, scheduledTokenAttr));
    EXPECT_TRUE(UserAuthHelper::GetTokenScheduleAttr(scheduledTokenAttr, schedule));
    EXPECT_TRUE(schedule.hasValidStartTime);
    EXPECT_EQ(schedule.validStartTime, 1000);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRedeemScheduledAuthToken001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> scheduleToken = {};
    scheduleToken.resize(1);
    std::vector<uint8_t> challenge = {1};
    sptr<IVerifyTokenCallback> callbackInterface(nullptr);
    EXPECT_EQ(service.RedeemScheduledAuthToken(challenge, scheduleToken, callbackInterface), INVALID_PARAMETERS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRedeemScheduledAuthToken002, TestSize.Level0)
{
    UserAuthService service;
    constexpr size_t maxScheduleTokenSize = 1024;
    constexpr size_t maxChallengeSize = MAX_CHALLENG_LEN;
    std::vector<uint8_t> scheduleToken = {};
    std::vector<uint8_t> challenge = {1};
    sptr<MockVerifyTokenCallback> testCallback(nullptr);
    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(3);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    EXPECT_EQ(service.RedeemScheduledAuthToken(challenge, scheduleToken, callbackInterface), INVALID_PARAMETERS);

    scheduleToken.resize(maxScheduleTokenSize + 1);
    EXPECT_EQ(service.RedeemScheduledAuthToken(challenge, scheduleToken, callbackInterface), INVALID_PARAMETERS);

    scheduleToken.resize(1);
    challenge.resize(maxChallengeSize + 1);
    EXPECT_EQ(service.RedeemScheduledAuthToken(challenge, scheduleToken, callbackInterface), INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRedeemScheduledAuthToken003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> scheduleToken = {};
    scheduleToken.resize(1);
    sptr<MockVerifyTokenCallback> testCallback(nullptr);
    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(2);
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    std::vector<uint8_t> challenge = {1};
    EXPECT_EQ(service.RedeemScheduledAuthToken(challenge, scheduleToken, callbackInterface),
        CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    EXPECT_EQ(service.RedeemScheduledAuthToken(challenge, scheduleToken, callbackInterface),
        CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRedeemScheduledAuthToken004, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> scheduleToken = {};
    scheduleToken.resize(1);
    sptr<MockVerifyTokenCallback> testCallback(nullptr);
    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(2);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> challenge = {1};
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    EXPECT_EQ(service.RedeemScheduledAuthToken(challenge, scheduleToken, callbackInterface),
        CAPABILITY_NOT_SUPPORTED);

    challenge.clear();
    EXPECT_EQ(service.RedeemScheduledAuthToken(challenge, scheduleToken, callbackInterface), INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _))
        .WillOnce([](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
            static const uint32_t USER_AUTH_TOKEN_LEN = 148;
            reuseInfo.token.resize(USER_AUTH_TOKEN_LEN);
            return HDF_SUCCESS;
        });

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> token;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, token), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> token;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, token), CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    std::vector<uint8_t> token;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, token), CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult004, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _))
        .WillOnce([](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
            return HDF_FAILURE;
        });

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> token;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, token), GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult005, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _))
        .WillOnce([](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
            return HDF_SUCCESS;
        });

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> token;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, token), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, GetAuthLockState001, TestSize.Level0)
{
    UserAuthService service;
    AuthType testAuthType = PIN;
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    int32_t ret = service.GetAuthLockState(testAuthType, testCallback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    ret = service.GetAuthLockState(testAuthType, testCallback);
    EXPECT_EQ(ret, SUCCESS);

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    ret = service.GetAuthLockState(testAuthType, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, GetAuthLockState002, TestSize.Level0)
{
    UserAuthService service;
    AuthType testAuthType = FACE;
    auto testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    OHOS::UserIam::UserAuth::IpcCommon::skipFlag_ = true;
    auto ret = service.GetAuthLockState(testAuthType, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_Utf8Title001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {FACE},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_Utf8Title002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {FACE},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    std::string longTitle(501, 'a');
    WidgetParamInner widgetParam = {
        .title = longTitle,
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_Utf8NaviBtn001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {FACE},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = "确定",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_Utf8NaviBtn002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {FACE},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    std::string longNaviBtn(61, 'a');
    WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = longNaviBtn,
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_CompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_CompanionDevice_002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE, AuthType::PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_CompanionDevice_006, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE, AuthType::FACE, AuthType::FINGERPRINT};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_CompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FINGERPRINT);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::FACE);
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_CompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_CompanionDevice_003, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::FINGERPRINT};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_004, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_CompanionDevice_003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FINGERPRINT);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::FACE);
    validAuthTypeList.push_back(AuthType::PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_CompanionDevice_004, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::PIN};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_CompanionDevice_005, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::FINGERPRINT};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "nav_btn";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_CompanionDevice_006, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::PIN};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "nav_btn";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_CompanionDevice_007, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::PIN};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_006, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_007, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN, AuthType::FACE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_008, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_009, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_012, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_CompanionDevice_013, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_CompanionDevice_PrivatePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE, AuthType::PRIVATE_PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_Fullscreen_CompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// moved from part01 to keep that file under the source-size gate
HWTEST_F(UserAuthServiceTest, UserAuthServiceGetEnrolledStateImplTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    int32_t apiVersion = 10000;
    int32_t authType = FACE;
    IpcEnrolledState enrolledState = {};
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::SetSkipUserFlag(true);
    EXPECT_EQ(service->GetEnrolledStateImpl(apiVersion, authType, enrolledState), GENERAL_ERROR);
    IpcCommon::SetSkipUserFlag(false);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetEnrolledState(_, _, _))
        .WillOnce(Return(NOT_ENROLLED));
    EXPECT_EQ(service->GetEnrolledStateImpl(apiVersion, authType, enrolledState), NOT_ENROLLED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetTemplatesByAuthTypeTest, TestSize.Level0)
{
    int32_t userId = 110;
    AuthType authType = FACE;
    std::vector<uint64_t> templateId;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _))
        .WillOnce([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            return HDF_FAILURE;
        });
    EXPECT_EQ(GetTemplatesByAuthType(userId, authType, templateId), GENERAL_ERROR);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAuthParamStrTest, TestSize.Level0)
{
    AuthParamInner authParam;
    RemoteAuthParam tmpAuthParam;
    std::optional<RemoteAuthParam> remoteAuthParam = RemoteAuthParam{};
    remoteAuthParam->collectorTokenId = std::make_optional<uint32_t>(1000000);
    EXPECT_NE(GetAuthParamStr(authParam, remoteAuthParam), "");
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyHelperTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    int32_t userId = 110;
    int32_t authType = 2;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _)).Times(1);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _))
        .WillOnce(Return(HDF_FAILURE));
    EXPECT_EQ(service->GetPropertyHelper(userId, authType, testKeys, callbackInterface), SUCCESS);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

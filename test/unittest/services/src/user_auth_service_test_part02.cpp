/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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
#include "mock_event_listener.h"
#include "mock_context.h"
#include "mock_iuser_auth_interface.h"
#include "mock_ipc_common.h"
#include "mock_modal_callback.h"
#include "mock_user_access_ctrl_callback.h"
#include "mock_user_auth_callback.h"
#include "mock_user_auth_service.h"
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

static void InitIpcAuthParamInner(IpcAuthParamInner &authParam,
    std::vector<uint8_t> &challenge, std::vector<int32_t> &authTypes, int32_t authTrustLevel)
{
    authParam.challenge = challenge;
    authParam.authTypes = authTypes;
    authParam.authTrustLevel = authTrustLevel;
}

static void InitIpcWidgetParamInner(IpcWidgetParamInner &widgetParam,
    const std::string &title, const std::string &navigationButtonText, int32_t windowMode)
{
    widgetParam.title = title;
    widgetParam.navigationButtonText = navigationButtonText;
    widgetParam.windowMode = windowMode;
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "确定", 0);
    sptr<IIamCallback> testUserAuthCallback(nullptr);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testUserAuthCallback, testModalCallback,
        contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, (uint64_t)0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_002, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_003, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_004, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_005, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_006, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_007, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes;
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(2);
    int32_t userId = 1;
    IpcCommon::GetCallingUserId(service, userId);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(FACE);
    ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_008, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {5};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_009, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {ALL};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_010, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, 50000);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TRUST_LEVEL_NOT_SUPPORT);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_011, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL1);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_012, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL1);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "WidgetParamTitle", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_013, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<IModalCallback> modalCallback = new MockModalCallback();
    EXPECT_NE(modalCallback, nullptr);
    auto *testModalCallback = static_cast<MockModalCallback *>(modalCallback.GetRefPtr());
    EXPECT_NE(testModalCallback, nullptr);
    EXPECT_CALL(*testModalCallback, SendCommand(_, _)).Times(0);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, modalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_014, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, 50000);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TRUST_LEVEL_NOT_SUPPORT);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_015, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
                .executorMatcher = 2,
                .executorSensorHint = 3,
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    ResourceNodePool::Instance().Insert(nullptr);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_016, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
                .executorMatcher = 2,
                .executorSensorHint = 3,
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault([](const Attributes &condition, Attributes &values) {
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0017, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
                .executorMatcher = 2,
                .executorSensorHint = 3,
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault([](const Attributes &condition, Attributes &values) {
            values.SetStringValue(Attributes::ATTR_PIN_SUB_TYPE, "test");
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0018, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault([acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0019, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault([acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, acquire);
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0020, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(0),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, acquire);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, acquire);
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0021, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {ALL};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(0),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, acquire);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, acquire);
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_022, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, acquire);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, acquire);
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_023, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    authParam.reuseUnlockResult.isReuse = true;
    authParam.reuseUnlockResult.reuseMode = AUTH_TYPE_IRRELEVANT;
    authParam.reuseUnlockResult.reuseDuration = 5 * 60 *1000;
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _)).Times(1);
    ON_CALL(*mockHdi, CheckReuseUnlockResult)
        .WillByDefault(
            [](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
                static const uint32_t USER_AUTH_TOKEN_LEN = 148;
                reuseInfo.token.resize(USER_AUTH_TOKEN_LEN);
                return HDF_SUCCESS;
            }
        );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(contextId, REUSE_AUTH_RESULT_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_024, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "确定", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                return HDF_ERR_INVALID_PARAM;
            }
        );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, HDF_ERR_INVALID_PARAM);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_025, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "确定", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                return PIN_EXPIRED;
            }
        );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_026, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::FACE);
                return HDF_SUCCESS;
            }
        );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_027, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::FINGERPRINT);
                return HDF_SUCCESS;
            }
        );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_028, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::PIN);
                return HDF_SUCCESS;
            }
        );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_029, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    authParam.isUserIdSpecified = true;
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::PIN);
                return HDF_SUCCESS;
            }
        );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_030, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    authParam.isUserIdSpecified = true;
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::PIN);
                return HDF_SUCCESS;
            }
        );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_031, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FACE, FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_032, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT, FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_033, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT, FACE, PRIVATE_PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "test", WindowModeType::DIALOG_BOX);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_CompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {static_cast<int32_t>(AuthType::COMPANION_DEVICE)};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "Companion Device Auth", "", WindowModeType::DIALOG_BOX);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(2);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).Times(1);
    ON_CALL(*mockHdi, GetValidSolution).WillByDefault([](auto userId, auto &authTypes,
        auto authTrustLevel, auto &validTypes) {
        validTypes = {AuthType::COMPANION_DEVICE};
        return HDF_SUCCESS;
    });
    ON_CALL(*mockHdi, GetCredential).WillByDefault([](auto userId, auto authType, auto &infos) {
        infos.push_back({.credentialId = 1, .executorIndex = 0, .templateId = 3,
            .authType = static_cast<HdiAuthType>(AuthType::COMPANION_DEVICE)});
        return HDF_SUCCESS;
    });
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode);
    ON_CALL(*resourceNode, GetProperty).WillByDefault([](auto &condition, auto &values) {
        values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, -1);
        values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
        return SUCCESS;
    });
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, BAD_CONTEXT_ID);
    service.CancelAuthOrIdentify(contextId, 0);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_CompanionDeviceWithPin_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {static_cast<int32_t>(AuthType::COMPANION_DEVICE), PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "Mixed Auth", "", WindowModeType::DIALOG_BOX);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).Times(0);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_CompanionDeviceWithPrivatePin_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {static_cast<int32_t>(AuthType::COMPANION_DEVICE),
        static_cast<int32_t>(AuthType::PRIVATE_PIN)};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "Mixed Auth", "", WindowModeType::DIALOG_BOX);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_CompanionDeviceHdiFail_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {static_cast<int32_t>(AuthType::COMPANION_DEVICE)};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "Companion Device Auth", "", WindowModeType::DIALOG_BOX);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).Times(1);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::COMPANION_DEVICE);
                return HDF_FAILURE;
            }
        );
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, HDF_FAILURE);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_FilterCompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    IpcAuthParamInner authParam;
    IpcWidgetParamInner widgetParam;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {AuthType::COMPANION_DEVICE, AuthType::FACE};
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    InitIpcWidgetParamInner(widgetParam, "Mixed Auth", "", WindowModeType::DIALOG_BOX);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).Times(1);
    ON_CALL(*mockHdi, GetValidSolution).WillByDefault([](auto, auto, auto, auto &v) {
        v = {AuthType::COMPANION_DEVICE, AuthType::FACE};
        return HDF_SUCCESS;
    });
    ON_CALL(*mockHdi, GetCredential).WillByDefault([](auto, auto t, auto &i) {
        (t == AuthType::COMPANION_DEVICE) ?
            i.push_back({.credentialId = 1, .executorIndex = 1, .templateId = 1,
                .authType = static_cast<HdiAuthType>(AuthType::COMPANION_DEVICE)}) :
            i.push_back({.credentialId = 2, .executorIndex = 2, .templateId = 2,
                .authType = static_cast<HdiAuthType>(AuthType::FACE)});
        return HDF_SUCCESS;
    });
    auto node1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*node1, GetExecutorIndex()).WillRepeatedly(Return(1));
    auto node2 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*node2, GetExecutorIndex()).WillRepeatedly(Return(2));
    ResourceNodePool::Instance().Insert(node1);
    ResourceNodePool::Instance().Insert(node2);
    auto prop = [](const Attributes &, Attributes &v) {
        v.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, -1);
        v.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
        return SUCCESS;
    };
    ON_CALL(*node1, GetProperty).WillByDefault(prop);
    ON_CALL(*node2, GetProperty).WillByDefault(prop);
    uint64_t contextId = 0;
    EXPECT_EQ(service.AuthWidget(apiVersion, authParam, widgetParam, testCallback,
        sptr<IModalCallback>(nullptr), contextId), SUCCESS);
    service.CancelAuthOrIdentify(contextId, 0);
    (void)ResourceNodePool::Instance().Delete(1);
    (void)ResourceNodePool::Instance().Delete(2);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_ThreeTypesCombo_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {
        static_cast<int32_t>(AuthType::FACE),
        static_cast<int32_t>(AuthType::FINGERPRINT),
        static_cast<int32_t>(AuthType::COMPANION_DEVICE)
    };
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "Three Types Auth", "", WindowModeType::DIALOG_BOX);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_CompanionDeviceWithPinAndPrivatePin_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {
        static_cast<int32_t>(AuthType::COMPANION_DEVICE),
        PIN,
        static_cast<int32_t>(AuthType::PRIVATE_PIN)
    };
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "Three Types Auth", "", WindowModeType::DIALOG_BOX);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesCombo_001, TestSize.Level0)
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
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), false);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesWithoutFace_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FINGERPRINT);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    validAuthTypeList.push_back(AuthType::PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesWithoutFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FACE);
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    validAuthTypeList.push_back(AuthType::PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesWithoutCompanion_001, TestSize.Level0)
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

HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterCompanionDevice_OnlyCompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> validType;
    validType.push_back(AuthType::COMPANION_DEVICE);
    service.FilterCompanionDevice(validType);
    EXPECT_EQ(validType.size(), 1);
    EXPECT_EQ(validType[0], AuthType::COMPANION_DEVICE);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterCompanionDevice_OnlyOtherTypes_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> validType;
    validType.push_back(AuthType::FACE);
    validType.push_back(AuthType::FINGERPRINT);
    service.FilterCompanionDevice(validType);
    EXPECT_EQ(validType.size(), 2);
    EXPECT_NE(validType[0], AuthType::COMPANION_DEVICE);
    EXPECT_NE(validType[1], AuthType::COMPANION_DEVICE);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterCompanionDevice_EmptyList_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> validType;
    service.FilterCompanionDevice(validType);
    EXPECT_EQ(validType.size(), 0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NaviBtnWithFaceFingerCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "navButton",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NaviBtnWithOnlyCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "navButton",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = para.userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
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
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_Fullscreen_OnlyFace_001, TestSize.Level0)
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
        .authTypes = {AuthType::FACE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_Fullscreen_OnlyFinger_001, TestSize.Level0)
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
        .authTypes = {AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(para, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_Fullscreen_OnlyCompanion_001, TestSize.Level0)
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
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
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
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_Fullscreen_FaceAndFinger_001, TestSize.Level0)
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
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
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
    IpcCommon::DeleteAllPermission();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

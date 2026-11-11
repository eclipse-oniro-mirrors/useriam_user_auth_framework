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
#include "mock_resource_node.h"
#include "mock_widget_callback_interface.h"
#include "mock_remote_auth_callback.h"
#include "resource_node_pool.h"
#include "user_auth_service.h"
#include "user_auth_helper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

namespace {
constexpr uint32_t INVALID_PIN_ALGO_TYPE = 100;
constexpr int32_t INVALID_GLOBAL_CONFIG_TYPE = 100;
constexpr int32_t TEST_USER_ID_1 = 100;
constexpr int32_t TEST_USER_ID_2 = 101;
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam004, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);

    param.type = PIN_ALGO_TYPE;
    param.value.pinAlgoType = PinEncrypAlgoType::AES_GCM;
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.authTypes.clear();
    param.authTypes.push_back(PIN);
    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.authTypes.clear();
    param.authTypes.push_back(PIN);
    param.value.pinAlgoType = INVALID_PIN_ALGO_TYPE;
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.value.pinAlgoType = PinEncrypAlgoType::AES_GCM;
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam005, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);

    param.type = PIN_ALGO_TYPE;
    param.authTypes.push_back(PIN);
    param.value.pinAlgoType = PinEncrypAlgoType::SM4;
    param.userIds.push_back(TEST_USER_ID_1);
    param.userIds.push_back(TEST_USER_ID_2);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam006, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);

    param.type = PIN_ALGO_TYPE;
    param.authTypes.push_back(PIN);
    param.value.pinAlgoType = PinEncrypAlgoType::AES_GCM;

    EXPECT_EQ(service.SetGlobalConfigParam(param), INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam007, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);

    param.type = DISABLE_PIN_DELETION;
    param.value.disablePinDeletion = true;
    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetGlobalConfigParam(param), INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam008, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);

    param.type = DISABLE_PIN_DELETION;
    param.value.disablePinDeletion = true;
    param.authTypes.push_back(PIN);
    EXPECT_EQ(service.SetGlobalConfigParam(param), INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam009, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    // the global config can only be set with both the internal and the enterprise device manager permission
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();

    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    param.type = PIN_EXPIRED_PERIOD;
    param.authTypes.push_back(PIN);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetUserConfigParam001, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::CHECK_SYSTEM_APP_FAILED);

    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);

    param.type = PIN_EXPIRED_PERIOD;
    param.authTypes.push_back(PIN);
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.userIds.push_back(TEST_USER_ID_1);
    param.userIds.push_back(TEST_USER_ID_2);
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.userIds.clear();
    param.userIds.push_back(TEST_USER_ID_1);
    param.type = ENABLE_STATUS;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.type = PIN_ALGO_TYPE;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.type = INVALID_GLOBAL_CONFIG_TYPE;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetUserConfigParam002, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);

    param.userIds.push_back(TEST_USER_ID_1);

    param.type = PIN_EXPIRED_PERIOD;
    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.authTypes.clear();
    param.authTypes.push_back(PIN);
    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.authTypes.clear();
    param.type = DISABLE_PIN_DELETION;
    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetUserConfigParam003, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);

    param.userIds.push_back(TEST_USER_ID_1);
    param.authTypes.push_back(PIN);

    param.type = PIN_EXPIRED_PERIOD;
    param.value.pinExpiredPeriod = 1000;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.type = DISABLE_PIN_DELETION;
    param.value.disablePinDeletion = true;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetUserConfigParam004, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);

    param.userIds.push_back(0);
    param.authTypes.push_back(PIN);

    // the configType whitelist is removed, all the config types are handed over to the engine layer
    param.type = PIN_EXPIRED_PERIOD;
    param.value.pinExpiredPeriod = 1000;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::CAPABILITY_NOT_SUPPORTED);

    param.type = ENABLE_STATUS;
    param.value.enableStatus = true;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::CAPABILITY_NOT_SUPPORTED);

    param.type = PIN_ALGO_TYPE;
    param.value.pinAlgoType = PinEncrypAlgoType::AES_GCM;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::CAPABILITY_NOT_SUPPORTED);

    param.type = DISABLE_PIN_DELETION;
    param.value.disablePinDeletion = true;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::CAPABILITY_NOT_SUPPORTED);

    param.type = INVALID_GLOBAL_CONFIG_TYPE;
    EXPECT_EQ(service.SetUserConfigParam(param), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterRemoteAuthCallback001, TestSize.Level0)
{
    UserAuthService service;
    sptr<IRemoteAuthCallback> testCallback = nullptr;
    EXPECT_EQ(service.RegisterRemoteAuthCallback(testCallback), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterRemoteAuthCallback002, TestSize.Level0)
{
    UserAuthService service;
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);

    EXPECT_EQ(service.RegisterRemoteAuthCallback(mockCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterRemoteAuthCallback003, TestSize.Level0)
{
    UserAuthService service;
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.RegisterRemoteAuthCallback(mockCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterRemoteAuthCallback004, TestSize.Level0)
{
    UserAuthService service;
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);

    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegisterRemoteAuthCallback(mockCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnregisterRemoteAuthCallback001, TestSize.Level0)
{
    UserAuthService service;
    EXPECT_EQ(service.UnregisterRemoteAuthCallback(), ResultCode::CHECK_SYSTEM_APP_FAILED);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.UnregisterRemoteAuthCallback(), ResultCode::CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnregisterRemoteAuthCallback002, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    IpcCommon::AddPermission(IS_SYSTEM_APP);

    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);
    EXPECT_EQ(service.RegisterRemoteAuthCallback(mockCallback), ResultCode::CHECK_PERMISSION_FAILED);
    EXPECT_EQ(service.UnregisterRemoteAuthCallback(), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyHelperSensorInfoEnrolledTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    ASSERT_NE(service, nullptr);
    int32_t userId = 110;
    AuthType authType = FINGERPRINT;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_SENSOR_INFO};
    sptr<MockGetExecutorPropertyCallback> testCallback(new (std::nothrow) MockGetExecutorPropertyCallback());
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _)).Times(1);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault([](int32_t, int32_t authType,
        std::vector<HdiCredentialInfo> &infos) {
        infos.push_back({.credentialId = 1, .executorIndex = 2, .templateId = 3,
            .authType = static_cast<HdiAuthType>(authType), .executorMatcher = 2, .executorSensorHint = 3});
        return HDF_SUCCESS;
    });

    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2, authType, ALL_IN_ONE);
    ASSERT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _)).WillByDefault([](const Attributes &condition, Attributes &values) {
        std::vector<uint64_t> tplIds;
        EXPECT_TRUE(condition.GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, tplIds));
        EXPECT_EQ(tplIds.size(), 1u);
        if (!tplIds.empty()) {
            EXPECT_EQ(tplIds[0], 3u);
        }
        return SUCCESS;
    });

    EXPECT_EQ(service->GetPropertyHelper(userId, authType, testKeys, callbackInterface), SUCCESS);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyHelperSensorInfoNotEnrolledTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    ASSERT_NE(service, nullptr);
    int32_t userId = 110;
    AuthType authType = FINGERPRINT;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_SENSOR_INFO};
    sptr<MockGetExecutorPropertyCallback> testCallback(new (std::nothrow) MockGetExecutorPropertyCallback());
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _)).Times(1);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault([](int32_t, int32_t, std::vector<HdiCredentialInfo> &) {
        // Not enrolled: return success with an empty credential list
        return HDF_SUCCESS;
    });

    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2, authType, ALL_IN_ONE);
    ASSERT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _)).WillByDefault([](const Attributes &condition, Attributes &values) {
        std::vector<uint64_t> tplIds;
        EXPECT_TRUE(condition.GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, tplIds));
        EXPECT_TRUE(tplIds.empty());
        return SUCCESS;
    });

    EXPECT_EQ(service->GetPropertyHelper(userId, authType, testKeys, callbackInterface), SUCCESS);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyHelperSensorInfoHdiFailTest, TestSize.Level0)
{
    // HDI query failure: do not return failure; templateIds stays empty and is forwarded to the executor
    auto service = Common::MakeShared<UserAuthService>();
    ASSERT_NE(service, nullptr);
    int32_t userId = 110;
    AuthType authType = FINGERPRINT;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_SENSOR_INFO};
    sptr<MockGetExecutorPropertyCallback> testCallback(new (std::nothrow) MockGetExecutorPropertyCallback());
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _)).Times(1);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillOnce(Return(HDF_FAILURE));

    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2, authType, ALL_IN_ONE);
    ASSERT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _)).WillByDefault([](const Attributes &condition, Attributes &values) {
        std::vector<uint64_t> tplIds;
        EXPECT_TRUE(condition.GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, tplIds));
        EXPECT_TRUE(tplIds.empty());
        return SUCCESS;
    });

    EXPECT_EQ(service->GetPropertyHelper(userId, authType, testKeys, callbackInterface), SUCCESS);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceDoPrepareRemoteAuthTest_003, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner testAuthParam = {};
    testAuthParam.authType = PIN;
    testAuthParam.userId= 110;

    Authentication::AuthenticationPara testPara = {};
    testPara.authType = PIN;
    testPara.userId = 110;
    RemoteAuthParam testRemotePara = {};
    std::string localNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    testRemotePara.verifierNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    testRemotePara.collectorNetworkId = "1234567891123456789212345678931234567894123456789512345678961235";
    EXPECT_EQ(service->ProcessAuthParamForRemoteAuth(testAuthParam, testPara, testRemotePara, localNetworkId), false);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckCallerPermissionForUserIdTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthParamInner paramInner = {};
    paramInner.isUserIdSpecified = true;
    IpcCommon::SetSkipUserFlag(true);
    EXPECT_EQ(service->CheckCallerPermissionForUserId(paramInner), GENERAL_ERROR);
    IpcCommon::SetSkipUserFlag(false);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolutionTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 100;
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType;
    validType.emplace_back(FACE);
    validType.emplace_back(PIN);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.clear();
            validTypes.emplace_back(PIN);
            validTypes.emplace_back(FACE);
            return SUCCESS;
        })
        .WillRepeatedly([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.clear();
            validTypes.emplace_back(FINGERPRINT);
            validTypes.emplace_back(FACE);
            return SUCCESS;
        });
    widgetParam.navigationButtonText = "face";
    EXPECT_EQ(service->CheckValidSolution(para, authParam, widgetParam, validType),
        INVALID_PARAMETERS);
    widgetParam.navigationButtonText.clear();
    authParam.authTypes.emplace_back(PRIVATE_PIN);
    EXPECT_EQ(service->CheckValidSolution(para, authParam, widgetParam, validType),
        INVALID_PARAMETERS);
    authParam.authTypes.clear();
    IpcCommon::SetSkipAccountVerifiedFlag(true);
    authParam.skipLockedBiometricAuth = false;
    EXPECT_EQ(service->CheckValidSolution(para, authParam, widgetParam, validType), TYPE_NOT_SUPPORT);
    IpcCommon::SetSkipAccountVerifiedFlag(false);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetCallerInfoTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    bool isUserIdSpecified = false;
    int32_t userId = 110;
    ContextFactory::AuthWidgetContextPara para = {};
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    IpcCommon::SetSkipUserFlag(true);
    EXPECT_EQ(service->GetCallerInfo(isUserIdSpecified, userId, para, contextCallback), GENERAL_ERROR);
    para.sdkVersion = 300000;
    EXPECT_EQ(service->GetCallerInfo(isUserIdSpecified, userId, para, contextCallback), GENERAL_ERROR);
    para.sdkVersion = 2;
    para.callerType = Security::AccessToken::TOKEN_INVALID;
    EXPECT_EQ(service->GetCallerInfo(isUserIdSpecified, userId, para, contextCallback), GENERAL_ERROR);
    para.callerType = Security::AccessToken::TOKEN_HAP;
    EXPECT_EQ(service->GetCallerInfo(isUserIdSpecified, userId, para, contextCallback), GENERAL_ERROR);
    IpcCommon::SetSkipUserFlag(false);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

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
#include <condition_variable>
#include <mutex>

#include "iam_common_defines.h"
#include "iam_ptr.h"

#include "executor_messenger_service.h"
#include "accesstoken_kit.h"
#include "mock_event_listener.h"
#include "mock_context.h"
#include "mock_iuser_auth_interface.h"
#include "mock_ipc_common.h"
#include "mock_user_auth_callback.h"
#include "mock_user_auth_service.h"
#include "mock_resource_node.h"
#include "mock_widget_callback_interface.h"
#include "resource_node_pool.h"
#include "user_auth_service.h"
#include "template_cache_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
extern int32_t GetTemplatesByAuthType(int32_t userId, AuthType authType, std::vector<uint64_t> &templateIds);
extern std::string GetAuthParamStr(const AuthParamInner &authParam, std::optional<RemoteAuthParam> &remoteAuthParam);
using namespace testing;
using namespace testing::ext;
void UserAuthServiceTest::SetUpTestCase()
{
}

void UserAuthServiceTest::TearDownTestCase()
{
}

void UserAuthServiceTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void UserAuthServiceTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

class SimpleSync {
public:
    explicit SimpleSync(int32_t count = 1) : count_(count) {}

    void Wait()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return count_ <= 0; });
    }

    void Notify()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        count_--;
        if (count_ <= 0) {
            cv_.notify_one();
        }
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    int32_t count_;
};

class ScopedPermission {
public:
    explicit ScopedPermission(Permission perm)
    {
        IpcCommon::AddPermission(perm);
    }
    ~ScopedPermission()
    {
        IpcCommon::DeleteAllPermission();
    }
};

class ScopedResourceNode {
public:
    explicit ScopedResourceNode(uint32_t executorIndex, int32_t getPropertyRet,
        AuthType authType = PIN, ExecutorRole executorRole = ALL_IN_ONE)
        : executorIndex_(executorIndex)
    {
        auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, authType, executorRole);
        EXPECT_NE(resourceNode, nullptr);
        EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
        MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
        ON_CALL(*node, GetProperty(_, _))
            .WillByDefault(Return(getPropertyRet));
    }
    ~ScopedResourceNode()
    {
        ResourceNodePool::Instance().Delete(executorIndex_);
    }
private:
    uint32_t executorIndex_;
};

static void SetupPropertyCallbackWithSync(sptr<MockGetExecutorPropertyCallback> &testCallback, SimpleSync &sync)
{
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<uint8_t> &extraInfo) {
            sync.Notify();
            return SUCCESS;
        });
}

static void SetupPropertyCallbackWithTwoSyncs(sptr<MockGetExecutorPropertyCallback> &testCallback, SimpleSync &sync)
{
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .Times(2)
        .WillRepeatedly([&sync](int32_t result, const std::vector<uint8_t> &extraInfo) {
            sync.Notify();
            return SUCCESS;
        });
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetEnrolledState001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 12;
    AuthType testAuthType = FACE;
    IpcEnrolledState testEnrolledState;
    uint16_t expectCredentialDigest = 23962;
    uint16_t expectCredentialCount = 1;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetEnrolledState(_, _, _))
        .Times(1)
        .WillOnce(
            [expectCredentialDigest, expectCredentialCount](int32_t userId, int32_t authType,
                HdiEnrolledState &hdiEnrolledState) {
                hdiEnrolledState.credentialDigest = expectCredentialDigest;
                hdiEnrolledState.credentialCount = expectCredentialCount;
                return HDF_SUCCESS;
            }
        );
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t funcResult = SUCCESS;
    int32_t ret = service.GetEnrolledState(testApiVersion, testAuthType, testEnrolledState, funcResult);
    EXPECT_EQ(funcResult, SUCCESS);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(expectCredentialDigest, testEnrolledState.credentialDigest);
    EXPECT_EQ(expectCredentialCount, testEnrolledState.credentialCount);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetEnrolledState002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 12;
    AuthType testAuthType = FACE;
    IpcEnrolledState testEnrolledState;
    uint16_t expectCredentialDigest = 0;
    uint16_t expectCredentialCount = 0;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetEnrolledState(_, _, _)).WillOnce(Return(GENERAL_ERROR));
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t funcResult = SUCCESS;
    int32_t ret = service.GetEnrolledState(testApiVersion, testAuthType, testEnrolledState, funcResult);
    EXPECT_EQ(funcResult, GENERAL_ERROR);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(expectCredentialDigest, testEnrolledState.credentialDigest);
    EXPECT_EQ(expectCredentialCount, testEnrolledState.credentialCount);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetEnrolledState003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 10;
    AuthType testAuthType = FACE;
    IpcEnrolledState testEnrolledState;
    uint16_t expectCredentialDigest = 0;
    uint16_t expectCredentialCount = 0;
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t funcResult = SUCCESS;
    int32_t ret = service.GetEnrolledState(testApiVersion, testAuthType, testEnrolledState, funcResult);
    EXPECT_EQ(funcResult, TYPE_NOT_SUPPORT);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(expectCredentialDigest, testEnrolledState.credentialDigest);
    EXPECT_EQ(expectCredentialCount, testEnrolledState.credentialCount);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetEnrolledState004, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 10;
    AuthType testAuthType = FACE;
    IpcEnrolledState testEnrolledState;
    uint16_t expectCredentialDigest = 0;
    uint16_t expectCredentialCount = 0;
    int32_t funcResult = SUCCESS;
    int32_t ret = service.GetEnrolledState(testApiVersion, testAuthType, testEnrolledState, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(expectCredentialDigest, testEnrolledState.credentialDigest);
    EXPECT_EQ(expectCredentialCount, testEnrolledState.credentialCount);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 10000;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL3;
    int32_t testUserId = 100;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _))
        .Times(1)
        .WillOnce(
            [](int32_t userId, int32_t authType, uint32_t authTrustLevel, int32_t &checkRet) {
                checkRet = SUCCESS;
                return HDF_SUCCESS;
            }
        );
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t funcResult = SUCCESS;
    int32_t ret = service.GetAvailableStatus(testApiVersion, testUserId, testAuthType, testAuthTrustLevel, funcResult);
    EXPECT_EQ(funcResult, SUCCESS);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 2;
    AuthType testAuthType = PIN;
    int32_t testUserId = 100;
    AuthTrustLevel testAuthTrustLevel = static_cast<AuthTrustLevel>(90000);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t funcResult = SUCCESS;
    int32_t ret = service.GetAvailableStatus(testApiVersion, testUserId, testAuthType,
        testAuthTrustLevel, funcResult);
    EXPECT_EQ(funcResult, TRUST_LEVEL_NOT_SUPPORT);
    EXPECT_EQ(ret, SUCCESS);
    testApiVersion = 10000;
    testAuthType = FACE;
    ret = service.GetAvailableStatus(testApiVersion, testUserId, testAuthType,
        testAuthTrustLevel, funcResult);
    EXPECT_EQ(funcResult, TRUST_LEVEL_NOT_SUPPORT);
    EXPECT_EQ(ret, SUCCESS);

    testAuthTrustLevel = ATL2;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(1);
    ON_CALL(*mockHdi, GetAvailableStatus)
        .WillByDefault(
            [](int32_t userId, int32_t authType, uint32_t authTrustLevel, int32_t &checkRet) {
                checkRet = TRUST_LEVEL_NOT_SUPPORT;
                return SUCCESS;
            }
        );
    ret = service.GetAvailableStatus(testApiVersion, testUserId, testAuthType,
        testAuthTrustLevel, funcResult);
    EXPECT_EQ(funcResult, TRUST_LEVEL_NOT_SUPPORT);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 10000;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    int32_t testUserId = 100;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).WillRepeatedly([]() {
        return HDF_FAILURE;
    });
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t funcResult = SUCCESS;
    int32_t ret = service.GetAvailableStatus(testApiVersion, testUserId, testAuthType, testAuthTrustLevel, funcResult);
    EXPECT_EQ(funcResult, GENERAL_ERROR);
    EXPECT_EQ(ret, SUCCESS);
    testApiVersion = 9;
    ret = service.GetAvailableStatus(testApiVersion, testUserId, testAuthType, testAuthTrustLevel, funcResult);
    EXPECT_EQ(funcResult, GENERAL_ERROR);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus004, TestSize.Level0)
{
    int32_t testApiVersion = 10000;
    AuthType testAuthType = PIN;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    int32_t testUserId = 100;

    auto service = Common::MakeShared<UserAuthService>();
    EXPECT_NE(service, nullptr);
    int32_t funcResult = SUCCESS;
    int32_t ret = service->GetAvailableStatus(testApiVersion, testUserId, testAuthType, testAuthTrustLevel,
        funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(ret, SUCCESS);

    ret = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(ret, SUCCESS);

    testAuthType = FACE;
    ret = service->GetAvailableStatus(testUserId, testApiVersion, testAuthType, testAuthTrustLevel,
        funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(ret, SUCCESS);

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    testAuthTrustLevel = static_cast<AuthTrustLevel>(0);
    ret = service->GetAvailableStatus(testApiVersion, testUserId, testAuthType, testAuthTrustLevel,
        funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(ret, SUCCESS);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    testAuthTrustLevel = static_cast<AuthTrustLevel>(0);
    ret = service->GetAvailableStatus(testApiVersion, testUserId, testAuthType, testAuthTrustLevel,
        funcResult);
    EXPECT_EQ(funcResult, TRUST_LEVEL_NOT_SUPPORT);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus005, TestSize.Level0)
{
    int32_t testApiVersion = 10000;
    AuthType testAuthType = PIN;
    AuthTrustLevel testAuthTrustLevel = ATL2;

    auto service = Common::MakeShared<UserAuthService>();
    EXPECT_NE(service, nullptr);
    int32_t funcResult = SUCCESS;
    int32_t ret = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel,
        funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(ret, SUCCESS);

    ret = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel,
        funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(ret, SUCCESS);

    testAuthType = FACE;
    ret = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel,
        funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(ret, SUCCESS);

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    testAuthTrustLevel = static_cast<AuthTrustLevel>(0);
    ret = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel,
        funcResult);
    EXPECT_EQ(funcResult, TRUST_LEVEL_NOT_SUPPORT);
    EXPECT_EQ(ret, SUCCESS);
    testAuthTrustLevel = ATL2;
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    testApiVersion = 2;
    testAuthType = PIN;
    ret = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel,
        funcResult);
    EXPECT_EQ(funcResult, TYPE_NOT_SUPPORT);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus006, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    EXPECT_NE(service, nullptr);
    int32_t testApiVersion = 10000;
    AuthType testAuthType = PIN;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::SetSkipUserFlag(true);
    int32_t funcResult = SUCCESS;
    int32_t res = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel,
        funcResult);
    IpcCommon::SetSkipUserFlag(false);
    EXPECT_EQ(funcResult, GENERAL_ERROR);
    EXPECT_EQ(res, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 123;
    AuthType testAuthType = PIN;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    std::promise<void> promise1, promise2;
    sptr<MockGetExecutorPropertyCallback> testCallback(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .WillOnce([&promise1](auto result, auto &extraInfo) { promise1.set_value(); return SUCCESS; })
        .WillOnce([&promise2](auto result, auto &extraInfo) { promise2.set_value(); return SUCCESS; });
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    promise1.get_future().get();
    promise2.get_future().get();
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 123;
    AuthType testAuthType = PIN;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault([](auto userId, auto authType, auto &infos) {
        infos.push_back({.credentialId = 1, .executorIndex = 2, .templateId = 3,
            .authType = static_cast<HdiAuthType>(1), .executorMatcher = 2, .executorSensorHint = 3});
        return HDF_SUCCESS;
    });
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _)).WillByDefault(Return(SUCCESS));
    std::promise<void> promise1, promise2;
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .WillOnce([&promise1](auto result, auto &extraInfo) { promise1.set_value(); return SUCCESS; })
        .WillOnce([&promise2](auto result, auto &extraInfo) { promise2.set_value(); return SUCCESS; });
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    callbackInterface = testCallback;
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    promise1.get_future().get();
    promise2.get_future().get();
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 123;
    AuthType testAuthType = PIN;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_REMAIN_TIMES, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    testKeys = {Attributes::ATTR_FREEZING_TIME, Attributes::ATTR_SIGNATURE};
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    testKeys = {Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, Attributes::ATTR_SIGNATURE};
    service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);

    testKeys = {Attributes::ATTR_SIGNATURE};
    service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);

    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault(Return(FAIL));
    std::promise<void> promise1;
    std::promise<void> promise2;
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .WillOnce([&promise1](int32_t result, const std::vector<uint8_t> &extraInfo) {
            promise1.set_value();
            return SUCCESS;
        })
        .WillOnce([&promise2](int32_t result, const std::vector<uint8_t> &extraInfo) {
            promise2.set_value();
            return SUCCESS;
        });
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    callbackInterface = testCallback;
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    promise1.get_future().get();
    promise2.get_future().get();
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty004, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 123;
    AuthType testAuthType = PIN;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault([](int32_t userId, int32_t authType,
        std::vector<HdiCredentialInfo> &infos) {
        infos.push_back({.credentialId = 1, .executorIndex = 2, .templateId = 3,
            .authType = static_cast<HdiAuthType>(1), .executorMatcher = 2, .executorSensorHint = 3});
        return HDF_SUCCESS;
    });
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2, FACE, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _)).WillByDefault(Return(SUCCESS));
    std::promise<void> promise1, promise2;
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .WillOnce([&promise1](auto result, auto &extraInfo) { promise1.set_value(); return SUCCESS; })
        .WillOnce([&promise2](auto result, auto &extraInfo) { promise2.set_value(); return SUCCESS; });
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    callbackInterface = testCallback;
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    promise1.get_future().get();
    promise2.get_future().get();
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty005, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 123;
    AuthType testAuthType = PIN;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential)
        .WillByDefault(
            [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
                HdiCredentialInfo tempInfo = {
                    .credentialId = 1,
                    .executorIndex = 2,
                    .templateId = 3,
                    .authType = static_cast<HdiAuthType>(1),
                    .executorMatcher = 2,
                    .executorSensorHint = 3,
                };
                infos.push_back(tempInfo);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2, PIN, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault(Return(SUCCESS));
    std::promise<void> promise;
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .WillOnce([&promise](int32_t result, const std::vector<uint8_t> &extraInfo) {
            promise.set_value();
            return SUCCESS;
        });
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    callbackInterface = testCallback;
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    promise.get_future().get();
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty006, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 123;
    AuthType testAuthType = FACE;
    std::vector<uint32_t> testKeys = {
        Attributes::ATTR_PIN_SUB_TYPE,
        Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION
    };
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
ON_CALL(*mockHdi, GetCredential).WillByDefault([](int32_t userId, int32_t authType,
        std::vector<HdiCredentialInfo> &infos) {
        infos.push_back({.credentialId = 1, .executorIndex = 2, .templateId = 3,
            .authType = static_cast<HdiAuthType>(1), .executorMatcher = 2, .executorSensorHint = 3});
        return HDF_SUCCESS;
    });
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2, FACE, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault(Return(SUCCESS));
    std::promise<void> promise;
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .WillOnce([&promise](int32_t result, const std::vector<uint8_t> &extraInfo) {
            promise.set_value();
            return SUCCESS;
        });
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    callbackInterface = testCallback;
    ret = service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    promise.get_future().get();
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetProperty001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 124;
    AuthType testAuthType = PIN;
    Attributes testAttr;
    std::promise<void> promise1;
    std::promise<void> promise2;
    sptr<MockSetExecutorPropertyCallback> testCallback(new (std::nothrow) MockSetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnSetExecutorPropertyResult(_))
        .WillOnce([&promise1](int32_t result) {
            promise1.set_value();
            return SUCCESS;
        })
        .WillOnce([&promise2](int32_t result) {
            promise2.set_value();
            return SUCCESS;
        });
    sptr<ISetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.SetProperty(testUserId, testAuthType, testAttr.Serialize(), callbackInterface);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    ret = service.SetProperty(testUserId, testAuthType, testAttr.Serialize(), callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    promise1.get_future().get();
    promise2.get_future().get();
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetProperty002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 124;
    AuthType testAuthType = PIN;
    Attributes testAttr;
    sptr<MockSetExecutorPropertyCallback> testCallback(nullptr);
    sptr<ISetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.SetProperty(testUserId, testAuthType, testAttr.Serialize(), callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, SetProperty(_))
        .WillByDefault(Return(SUCCESS));
    std::promise<void> promise1;
    std::promise<void> promise2;
    testCallback = sptr<MockSetExecutorPropertyCallback>(new (std::nothrow) MockSetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnSetExecutorPropertyResult(_))
        .WillOnce([&promise1](int32_t result) {
            promise1.set_value();
            return SUCCESS;
        })
        .WillOnce([&promise2](int32_t result) {
            promise2.set_value();
            return SUCCESS;
        });
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    callbackInterface = testCallback;
    ret = service.SetProperty(testUserId, testAuthType, testAttr.Serialize(), callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    ret = service.SetProperty(testUserId, testAuthType, testAttr.Serialize(), callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    promise1.get_future().get();
    promise2.get_future().get();
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetProperty003, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    int32_t testUserId = 124;
    AuthType testAuthType = FACE;
    Attributes testAtrr;
    std::promise<void> promise1;
    std::promise<void> promise2;
    sptr<MockSetExecutorPropertyCallback> testCallback(new (std::nothrow) MockSetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnSetExecutorPropertyResult(_))
        .WillOnce([&promise1](int32_t result) {
            promise1.set_value();
            return SUCCESS;
        })
        .WillOnce([&promise2](int32_t result) {
            promise2.set_value();
            return SUCCESS;
        });
    sptr<ISetExecutorPropertyCallback> callbackInterface = testCallback;
    ResourceNodePool::Instance().DeleteAll();
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2, FACE, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, SetProperty(_))
        .WillByDefault(Return(FAIL));
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    auto ret = service->SetProperty(testUserId, testAuthType, testAtrr.Serialize(), callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    ret = service->SetProperty(testUserId, testAuthType, testAtrr.Serialize(), callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    promise1.get_future().get();
    promise2.get_future().get();
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 9;
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.challenge = {1, 2, 3, 4};
    ipcAuthParamInner.authType = FACE;
    ipcAuthParamInner.authTrustLevel = ATL2;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _))
        .WillOnce(
            [](int32_t result, const std::vector<uint8_t> &extraInfo) {
                return SUCCESS;
            }
        );

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).WillByDefault(Return(HDF_FAILURE));

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    handler->EnsureTask([]() {});
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 9;
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.challenge = {1, 2, 3, 4};
    ipcAuthParamInner.authType = FACE;
    ipcAuthParamInner.authTrustLevel = ATL2;
    sptr<MockUserAuthCallback> testCallback(nullptr);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, 0);

    testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    ipcAuthParamInner.authTrustLevel = static_cast<AuthTrustLevel>(90000);
    callbackInterface = testCallback;
    ret = service.Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, TRUST_LEVEL_NOT_SUPPORT);
    EXPECT_EQ(contextId, 0);

    ipcAuthParamInner.authType = PIN;
    ipcAuthParamInner.authTrustLevel = ATL1;
    ret = service.Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_EQ(contextId, 0);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    handler->EnsureTask([]() {});
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 9;
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.challenge = {1, 2, 3, 4};
    ipcAuthParamInner.authType = PIN;
    ipcAuthParamInner.authTrustLevel = ATL2;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);

    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(contextId, 0);

    ipcAuthParamInner.authType = FACE;
    ret = service.Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(contextId, 0);

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).WillByDefault(Return(NOT_ENROLLED));
    ret = service.Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);

    testApiVersion = 8;
    ret = service.Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    handler->EnsureTask([]() {});
    IpcCommon::DeleteAllPermission();
}

static void MockForUserAuthHdi(std::shared_ptr<Context> &context, std::promise<void> &promise)
{
    const uint32_t testScheduleId = 20;
    const uint32_t testExecutorIndex = 60;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _))
        .WillRepeatedly([&context](uint64_t contextId, const HdiAuthParamExt &param,
            std::vector<HdiScheduleInfo> &scheduleInfos) {
            HdiScheduleInfo scheduleInfo = {};
            scheduleInfo.authType = HdiAuthType::FACE;
            scheduleInfo.scheduleId = testScheduleId;
            scheduleInfo.executorIndexes.push_back(testExecutorIndex);
            std::vector<uint8_t> executorMessages;
            executorMessages.resize(1);
            scheduleInfo.executorMessages.push_back(executorMessages);
            scheduleInfos.push_back(scheduleInfo);
            context = ContextPool::Instance().Select(contextId).lock();
            return HDF_SUCCESS;
        });
    
    EXPECT_CALL(*mockHdi, UpdateAuthenticationResult(_, _, _, _)).WillOnce(Return(HDF_SUCCESS));
    EXPECT_CALL(*mockHdi, CancelAuthentication(_))
        .WillOnce([&promise](uint64_t contextId) {
            promise.set_value();
            return HDF_SUCCESS;
        });
}

static void MockForAuthResourceNode(std::shared_ptr<MockResourceNode> &resourceNode)
{
    const uint32_t testScheduleId = 20;
    const uint32_t testExecutorIndex = 60;
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(testExecutorIndex));
    EXPECT_CALL(*resourceNode, GetAuthType()).WillRepeatedly(Return(FACE));
    EXPECT_CALL(*resourceNode, GetExecutorRole()).WillRepeatedly(Return(ALL_IN_ONE));
    EXPECT_CALL(*resourceNode, GetExecutorMatcher()).WillRepeatedly(Return(0));
    EXPECT_CALL(*resourceNode, GetExecutorPublicKey()).WillRepeatedly(Return(std::vector<uint8_t>()));
    EXPECT_CALL(*resourceNode, BeginExecute(_, _, _))
        .WillOnce([](uint64_t scheduleId, const std::vector<uint8_t> &publicKey, const Attributes &command) {
            auto messenger = ExecutorMessengerService::GetInstance();
            EXPECT_NE(messenger, nullptr);
            auto finalResult = Common::MakeShared<Attributes>();
            EXPECT_NE(finalResult, nullptr);
            std::vector<uint8_t> scheduleResult = {1, 2, 3, 4};
            EXPECT_TRUE(finalResult->SetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult));
            EXPECT_EQ(messenger->Finish(testScheduleId, SUCCESS, finalResult->Serialize()), SUCCESS);
            return SUCCESS;
        });
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth004, TestSize.Level0)
{
    UserAuthService service;
    int32_t testApiVersion = 9;
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.challenge = {1, 2, 3, 4};
    ipcAuthParamInner.authType = FACE;
    ipcAuthParamInner.authTrustLevel = ATL2;
    std::shared_ptr<Context> context = nullptr;

    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _))
        .WillOnce(
            [&context](int32_t result, const std::vector<uint8_t>  &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
                if (context != nullptr) {
                    context->Stop();
                }
                return SUCCESS;
            }
        );

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    std::promise<void> promise;
    MockForUserAuthHdi(context, promise);

    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    MockForAuthResourceNode(resourceNode);

    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));

    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);
    promise.get_future().get();

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(60));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    handler->EnsureTask([]() {});
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth005, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    int32_t testApiVersion = 9;
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.challenge = {1, 2, 3, 4};
    ipcAuthParamInner.authType = FACE;
    ipcAuthParamInner.authTrustLevel = ATL2;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    sptr<IIamCallback> callbackInterface = testCallback;
    IpcCommon::SetSkipCallerFlag(true);
    uint64_t contextId = 0;
    int32_t ret = service->Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    IpcCommon::SetSkipCallerFlag(false);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::SetSkipUserFlag(true);
    ret = service->Auth(testApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::SetSkipUserFlag(false);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser001, TestSize.Level0)
{
    UserAuthService service;
    IpcAuthParamInner authParam = {
        .userId = 125,
        .challenge = {1, 2, 3, 4},
        .authType = FACE,
        .authTrustLevel = ATL2,
    };
    IpcRemoteAuthParam remoteAuthParam = {
        .isHasRemoteAuthParam = false,
    };
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser002, TestSize.Level0)
{
    UserAuthService service;
    IpcAuthParamInner authParam = {
        .userId = 125,
        .challenge = {1, 2, 3, 4},
        .authType = FACE,
        .authTrustLevel = ATL2,
    };
    IpcRemoteAuthParam remoteAuthParam = {
        .isHasRemoteAuthParam = false,
    };
    sptr<MockUserAuthCallback> testCallback(nullptr);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, 0);

    testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(90000);
    callbackInterface = testCallback;
    ret = service.AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser003, TestSize.Level0)
{
    UserAuthService service;
    IpcAuthParamInner authParam = {
        .userId = 125,
        .challenge = {1, 2, 3, 4},
        .authType = FACE,
        .authTrustLevel = ATL2,
    };
    IpcRemoteAuthParam remoteAuthParam = {
        .isHasRemoteAuthParam = false,
    };
    std::shared_ptr<Context> context = nullptr;

    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const std::vector<uint8_t> &extraInfo) {
                EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
                return SUCCESS;
            }
        )
        .WillOnce(
            [&context](int32_t result, const std::vector<uint8_t> &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
                if (context != nullptr) {
                    context->Stop();
                }
                return SUCCESS;
            }
        );

    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(contextId, 0);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    std::promise<void> promise;
    MockForUserAuthHdi(context, promise);

    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    MockForAuthResourceNode(resourceNode);
    
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));

    ret = service.AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);
    promise.get_future().get();

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(60));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser004, TestSize.Level0)
{
    UserAuthService service;
    IpcAuthParamInner authParam = {
        .userId = 125,
        .challenge = {1, 2, 3, 4},
        .authType = FACE,
        .authTrustLevel = ATL2,
    };
    IpcRemoteAuthParam remoteAuthParam = {
        .isHasRemoteAuthParam = true,
        .verifierNetworkId = "123",
        .collectorNetworkId = "1233324321423412344134",
    };
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser005, TestSize.Level0)
{
    UserAuthService service;
    IpcAuthParamInner authParam = {
        .userId = 125,
        .challenge = {1, 2, 3, 4},
        .authType = PIN,
        .authTrustLevel = ATL2,
    };
    IpcRemoteAuthParam remoteAuthParam = {
        .isHasRemoteAuthParam = true,
        .verifierNetworkId = "123",
        .collectorNetworkId = "1233324321423412344134",
    };
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t  ret = service.AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser006, TestSize.Level0)
{
    UserAuthService service;
    IpcAuthParamInner authParam = {
        .userId = -1,
        .challenge = {1, 2, 3, 4},
        .authType = PIN,
        .authTrustLevel = ATL2,
    };
    IpcRemoteAuthParam remoteAuthParam = {
        .isHasRemoteAuthParam = true,
        .verifierNetworkId = "123",
        .collectorNetworkId = "1233324321423412344134",
    };
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser007, TestSize.Level0)
{
    UserAuthService service;
    IpcAuthParamInner authParam = {
        .userId = -1,
        .challenge = {1, 2, 3, 4},
        .authType = PIN,
        .authTrustLevel = ATL2,
    };
    IpcRemoteAuthParam remoteAuthParam = {
        .isHasRemoteAuthParam = true,
        .verifierNetworkId = "123",
        .collectorNetworkId = "1233324321423412344134",
        .collectorTokenId = 123123,
    };
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _)).Times(0);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser008, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    IpcAuthParamInner authParam = {
        .userId = -1,
        .challenge = {1, 2, 3, 4},
        .authType = PIN,
        .authTrustLevel = ATL2,
    };
    IpcRemoteAuthParam remoteAuthParam = {
        .isHasRemoteAuthParam = true,
        .verifierNetworkId = "123",
        .collectorNetworkId = "1233324321423412344134",
        .collectorTokenId = 123123,
    };
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    IpcCommon::SetSkipCallerFlag(true);
    int32_t ret = service->AuthUser(authParam, remoteAuthParam, callbackInterface, contextId);
    EXPECT_NE(ret, SUCCESS);
    IpcCommon::SetSkipCallerFlag(false);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceInitRemoteAuthParam_001, TestSize.Level0)
{
    UserAuthService service;
    IpcRemoteAuthParam ipcRemoteAuthParam = {
        .isHasVerifierNetworkId = true,
        .isHasRemoteAuthParam = true,
        .isHasCollectorNetworkId = true,
        .isHasCollectorTokenId = true,
        .verifierNetworkId = "123",
        .collectorNetworkId = "1233324321423412344134",
        .collectorTokenId = 123123,
    };
    std::optional<RemoteAuthParam> remoteAuthParam = {};
    RemoteAuthParam param = {};
    param.verifierNetworkId = "123";
    param.collectorNetworkId = "1233324321423412344134";
    remoteAuthParam = param;
    EXPECT_NO_THROW(service.InitRemoteAuthParam(ipcRemoteAuthParam, remoteAuthParam));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceProcessPinExpired_001, TestSize.Level0)
{
    UserAuthService service;
    int ret = PIN_EXPIRED;
    AuthParamInner authParam = {
        .authTypes = {FACE, PIN, PRIVATE_PIN},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validType = {FACE, PIN, PRIVATE_PIN};
    ContextFactory::AuthWidgetContextPara para = {
        .isPinExpired = true
    };
    EXPECT_NO_THROW(service.ProcessPinExpired(ret, authParam, validType, para));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceIdentify001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, BeginIdentification(_, _, _, _, _)).Times(1);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.Identify(testChallenge, testAuthType, callbackInterface, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceIdentify002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    sptr<MockUserAuthCallback> testCallback(nullptr);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.Identify(testChallenge, testAuthType, callbackInterface, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, 0);

    testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    testAuthType = PIN;
    callbackInterface = testCallback;
    ret =  service.Identify(testChallenge, testAuthType, callbackInterface, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

static void MockForIdentifyHdi(std::shared_ptr<Context> &context, std::promise<void> &promise)
{
    const uint32_t testExecutorIndex = 60;
    const uint32_t testscheduleId = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginIdentification(_, _, _, _, _))
        .WillRepeatedly([&context](uint64_t contextId, int32_t authType, const std::vector<uint8_t> &challenge,
            uint32_t executorId, HdiScheduleInfo &scheduleInfo) {
            scheduleInfo.authType = HdiAuthType::FACE;
            scheduleInfo.scheduleId = testscheduleId;
            scheduleInfo.executorIndexes.push_back(testExecutorIndex);
            std::vector<uint8_t> executorMessages;
            executorMessages.resize(1);
            scheduleInfo.executorMessages.push_back(executorMessages);
            context = ContextPool::Instance().Select(contextId).lock();
            return HDF_SUCCESS;
        });
    
    EXPECT_CALL(*mockHdi, UpdateIdentificationResult(_, _, _)).WillOnce(Return(HDF_SUCCESS));
    EXPECT_CALL(*mockHdi, CancelIdentification(_))
        .WillOnce([&promise](uint64_t contextId) {
            promise.set_value();
            return HDF_SUCCESS;
        });
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceIdentify003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    std::shared_ptr<Context> context = nullptr;

    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const std::vector<uint8_t> &extraInfo) {
                EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
                return SUCCESS;
            }
        )
        .WillOnce(
            [&context](int32_t result, const std::vector<uint8_t> &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
                if (context != nullptr) {
                    context->Stop();
                }
                return SUCCESS;
            }
        );

    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.Identify(testChallenge, testAuthType, callbackInterface, contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(contextId, 0);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    std::promise<void> promise;
    MockForIdentifyHdi(context, promise);

    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    MockForAuthResourceNode(resourceNode);
    
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));

    contextId = service.Identify(testChallenge, testAuthType, callbackInterface, contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    promise.get_future().get();

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(60));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCancelAuthOrIdentify_001, TestSize.Level0)
{
    UserAuthService service;
    uint64_t testContextId = 12355236;
    int32_t cancelReason = 0;
    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId, cancelReason), CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId, cancelReason), INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCancelAuthOrIdentify_002, TestSize.Level0)
{
    UserAuthService service;
    uint64_t testContextId = 0x5678;
    uint32_t tokenId = 0x1234;
    int32_t cancelReason = 0;

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::SetAccessTokenId(0, true);
    auto context = Common::MakeShared<MockContext>();
    EXPECT_NE(context, nullptr);
    EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(testContextId));
    EXPECT_CALL(*context, GetLatestError()).WillRepeatedly(Return(GENERAL_ERROR));
    EXPECT_CALL(*context, GetTokenId()).WillRepeatedly(Return(tokenId));
    EXPECT_CALL(*context, Stop())
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));

    EXPECT_TRUE(ContextPool::Instance().Insert(context));

    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId, cancelReason), CHECK_PERMISSION_FAILED);
    IpcCommon::SetAccessTokenId(tokenId, true);

    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId, cancelReason), SUCCESS);
    EXPECT_TRUE(ContextPool::Instance().Delete(testContextId));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetVersion, TestSize.Level0)
{
    UserAuthService service;
    int32_t version = -1;
    EXPECT_EQ(service.GetVersion(version), CHECK_PERMISSION_FAILED);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.GetVersion(version), SUCCESS);
    EXPECT_EQ(version, 1);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceStartRemoteAuthInvokerContext, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {
        .userId = 125,
        .challenge = {1, 2, 3, 4},
        .authType = FACE,
        .authTrustLevel = ATL2,
    };
    RemoteAuthInvokerContextParam remoteAuthInvokerContextParam;
    remoteAuthInvokerContextParam.connectionName = "";
    remoteAuthInvokerContextParam.verifierNetworkId = "123";
    remoteAuthInvokerContextParam.collectorNetworkId = "123123123";
    remoteAuthInvokerContextParam.tokenId = 123;
    remoteAuthInvokerContextParam.collectorTokenId = 123123;
    remoteAuthInvokerContextParam.callerName = "4123";
    remoteAuthInvokerContextParam.callerType = Security::AccessToken::TOKEN_HAP;
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_EQ(service.StartRemoteAuthInvokerContext(authParam, remoteAuthInvokerContextParam, contextCallback),
    SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServicePrepareRemoteAuth_001, TestSize.Level0)
{
    UserAuthService service;
    const std::string networkId = "12312312313";
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    sptr<IIamCallback> callbackInterface = testCallback;
    EXPECT_EQ(service.PrepareRemoteAuth(networkId, callbackInterface), SUCCESS);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.PrepareRemoteAuth(networkId, callbackInterface), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServicePrepareRemoteAuth_002, TestSize.Level0)
{
    UserAuthService service;
    const std::string networkId = "";
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    sptr<IIamCallback> callbackInterface = testCallback;
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.PrepareRemoteAuth(networkId, callbackInterface), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCompleteRemoteAuthParam_001, TestSize.Level0)
{
    UserAuthService service;
    const std::string localNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    RemoteAuthParam remoteAuthParam = {};
    remoteAuthParam.verifierNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    remoteAuthParam.collectorNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCompleteRemoteAuthParam_002, TestSize.Level0)
{
    UserAuthService service;
    const std::string localNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    RemoteAuthParam remoteAuthParam = {};
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), false);
    remoteAuthParam.verifierNetworkId = "123";
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), false);
    remoteAuthParam.verifierNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), true);
    remoteAuthParam.collectorNetworkId = "123";
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), false);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCompleteRemoteAuthParam_003, TestSize.Level0)
{
    UserAuthService service;
    const std::string localNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    RemoteAuthParam remoteAuthParam = {};
    remoteAuthParam.collectorNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), true);
    remoteAuthParam.verifierNetworkId = "1234567891123456789212345678931234567894123456789512345678961233";
    remoteAuthParam.collectorNetworkId = "1234567891123456789212345678931234567894123456789512345678961233";
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), false);
    remoteAuthParam.verifierNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    remoteAuthParam.collectorNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), true);
    remoteAuthParam.verifierNetworkId = "1234567891123456789212345678931234567894123456789512345678961233";
    remoteAuthParam.collectorNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), true);
    remoteAuthParam.verifierNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    remoteAuthParam.collectorNetworkId = "1234567891123456789212345678931234567894123456789512345678961233";
    EXPECT_EQ(service.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId), true);
}


static void MockGetCredentialById()
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredentialById(_, _))
        .WillByDefault([](uint64_t credentialId, HdiCredentialInfo &info) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 2,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
                .executorMatcher = 2,
                .executorSensorHint = 3,
            };
            info = tempInfo;
            return HDF_SUCCESS;
        });
}

static void SetupResourceNodeWithGetProperty(uint32_t executorIndex, int32_t getPropertyRet,
    AuthType authType = PIN, ExecutorRole executorRole = ALL_IN_ONE)
{
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, authType, executorRole);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault(Return(getPropertyRet));
}

static void SetupPropertyCallbackWithOnePromise(sptr<MockGetExecutorPropertyCallback> &testCallback,
    std::promise<void> &promise)
{
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .WillOnce([&promise](int32_t result, const std::vector<uint8_t> &extraInfo) {
            promise.set_value();
            return SUCCESS;
        });
}

static void SetupPropertyCallbackWithTwoPromises(sptr<MockGetExecutorPropertyCallback> &testCallback,
    std::promise<void> &promise1, std::promise<void> &promise2)
{
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _))
        .WillOnce([&promise1](int32_t result, const std::vector<uint8_t> &extraInfo) {
            promise1.set_value();
            return SUCCESS;
        })
        .WillOnce([&promise2](int32_t result, const std::vector<uint8_t> &extraInfo) {
            promise2.set_value();
            return SUCCESS;
        });
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyById001, TestSize.Level0)
{
    UserAuthService service;
    uint64_t testCredentialId = 1;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredentialById(_, _)).Times(1);
    SimpleSync sync(2);
    sptr<MockGetExecutorPropertyCallback> testCallback;
    SetupPropertyCallbackWithTwoSyncs(testCallback, sync);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    {
        ScopedPermission permission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
        EXPECT_EQ(ret, SUCCESS);
        sync.Wait();
    }
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyById002, TestSize.Level0)
{
    UserAuthService service;
    uint64_t testCredentialId = 1;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredentialById(_, _)).Times(2);
    MockGetCredentialById();
    ScopedResourceNode node(2, FAIL);
    SimpleSync sync(2);
    SetupPropertyCallbackWithTwoSyncs(testCallback, sync);
    {
        ScopedPermission permission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        callbackInterface = testCallback;
        ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
        EXPECT_EQ(ret, SUCCESS);
        ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
        EXPECT_EQ(ret, SUCCESS);
        sync.Wait();
    }
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyById003, TestSize.Level0)
{
    UserAuthService service;
    uint64_t testCredentialId = 1;
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret;

    std::vector<std::vector<uint32_t>> testKeyList = {
        {Attributes::ATTR_REMAIN_TIMES, Attributes::ATTR_SIGNATURE},
        {Attributes::ATTR_FREEZING_TIME, Attributes::ATTR_SIGNATURE},
        {Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, Attributes::ATTR_SIGNATURE},
        {Attributes::ATTR_SIGNATURE}
    };

    for (const auto &testKeys : testKeyList) {
        ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
        EXPECT_EQ(ret, INVALID_PARAMETERS);
    }

    ScopedResourceNode node(2, SUCCESS);
    SimpleSync sync;
    SetupPropertyCallbackWithSync(testCallback, sync);
    {
        ScopedPermission permission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        callbackInterface = testCallback;
        ret = service.GetPropertyById(testCredentialId, {Attributes::ATTR_SIGNATURE}, callbackInterface);
        EXPECT_EQ(ret, SUCCESS);
        sync.Wait();
    }
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyById004, TestSize.Level0)
{
    UserAuthService service;
    uint64_t testCredentialId = 1;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredentialById(_, _)).Times(1);
    MockGetCredentialById();
    ScopedResourceNode node(2, SUCCESS, FACE, ALL_IN_ONE);
    SimpleSync sync;
    SetupPropertyCallbackWithSync(testCallback, sync);
    {
        ScopedPermission permission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        callbackInterface = testCallback;
        ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
        EXPECT_EQ(ret, SUCCESS);
        sync.Wait();
    }
}

static void MockGetCredentialByIdForFace()
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredentialById(_, _))
        .WillByDefault([](uint64_t credentialId, HdiCredentialInfo &info) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 2,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(2),
                .executorMatcher = 2,
                .executorSensorHint = 3,
            };
            info = tempInfo;
            return HDF_SUCCESS;
        });
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyById005, TestSize.Level0)
{
    UserAuthService service;
    uint64_t testCredentialId = 1;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredentialById(_, _)).Times(1);
    MockGetCredentialById();
    ScopedResourceNode node(2, SUCCESS, PIN, ALL_IN_ONE);
    SimpleSync sync;
    SetupPropertyCallbackWithSync(testCallback, sync);
    {
        ScopedPermission permission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        callbackInterface = testCallback;
        ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
        EXPECT_EQ(ret, SUCCESS);
        sync.Wait();
    }
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyById006, TestSize.Level0)
{
    UserAuthService service;
    uint64_t testCredentialId = 1;
    std::vector<uint32_t> testKeys = {
        Attributes::ATTR_PIN_SUB_TYPE,
        Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION
    };
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredentialById(_, _)).Times(1);
    MockGetCredentialByIdForFace();
    ScopedResourceNode node(2, FAIL, FACE, ALL_IN_ONE);
    SimpleSync sync;
    SetupPropertyCallbackWithSync(testCallback, sync);
    {
        ScopedPermission permission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        callbackInterface = testCallback;
        ret = service.GetPropertyById(testCredentialId, testKeys, callbackInterface);
        EXPECT_EQ(ret, SUCCESS);
        sync.Wait();
    }
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetPropertyById007, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    uint64_t testCredentialId = 1;
    std::vector<uint32_t> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    SimpleSync sync(2);
    sptr<MockGetExecutorPropertyCallback> testCallback;
    SetupPropertyCallbackWithTwoSyncs(testCallback, sync);
    sptr<IGetExecutorPropertyCallback> callbackInterface = testCallback;
    int32_t ret = service->GetPropertyById(testCredentialId, testKeys, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredentialById(_, _))
        .WillByDefault(Return(HDF_FAILURE));
    {
        ScopedPermission permission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        ret = service->GetPropertyById(testCredentialId, testKeys, callbackInterface);
        EXPECT_EQ(ret, SUCCESS);
        sync.Wait();
    }
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceProcessAuthParamForRemoteAuth_InvalidAuthType, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    Authentication::AuthenticationPara para = {};
    RemoteAuthParam remoteAuthParam = {};
    std::string localNetworkId = "local123";
    para.authType = AuthType::FACE;
    EXPECT_FALSE(service.ProcessAuthParamForRemoteAuth(authParam, para, remoteAuthParam, localNetworkId));
    para.authType = AuthType::PIN;
    authParam.userId = -1;
    EXPECT_FALSE(service.ProcessAuthParamForRemoteAuth(authParam, para, remoteAuthParam, localNetworkId));
    authParam.userId = 100;
    EXPECT_FALSE(service.ProcessAuthParamForRemoteAuth(authParam, para, remoteAuthParam, localNetworkId));
    localNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    remoteAuthParam.verifierNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    remoteAuthParam.collectorNetworkId = "1234567891123456789212345678931234567894123456789512345678961234";
    para.tokenId = 789;
    EXPECT_TRUE(service.ProcessAuthParamForRemoteAuth(authParam, para, remoteAuthParam, localNetworkId));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParamTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    AuthType authType = FACE;
    int32_t callerType = Security::AccessToken::TOKEN_HAP;
    std::string callerName = "123456";
    AuthTrustLevel testAtl = ATL2;
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::SetSkipUserFlag(true);
    EXPECT_EQ(service->CheckAuthPermissionAndParam(authType, callerType, callerName, testAtl),
        CHECK_PERMISSION_FAILED);
    IpcCommon::SetSkipUserFlag(false);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceStartAuthContextTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    int32_t testApiVersion = 10000;
    Authentication::AuthenticationPara para = {};
    bool testNeedSubscribeAppState = false;
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_NE(service->StartAuthContext(testApiVersion, para, contextCallback, testNeedSubscribeAppState),
        BAD_CONTEXT_ID);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceStartLocalRemoteAuthContextTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    Authentication::AuthenticationPara para = {};
    LocalRemoteAuthContextParam contextPara = {};
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_EQ(service->StartLocalRemoteAuthContext(para, contextPara, contextCallback),
        BAD_CONTEXT_ID);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceDoPrepareRemoteAuthTest_001, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    std::string testNetworkId = "123456";
    sptr<MockUserAuthCallback> testCallback(nullptr);
    sptr<IIamCallback> callbackInterface = testCallback;
    EXPECT_EQ(service->PrepareRemoteAuthInner(testNetworkId, callbackInterface),
        INVALID_PARAMETERS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceDoPrepareRemoteAuthTest_002, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    std::string testNetworkId = "123456";
    sptr<MockUserAuthCallback> testCallback(nullptr);
    sptr<IIamCallback> callbackInterface = testCallback;
    EXPECT_EQ(service->PrepareRemoteAuth(testNetworkId, callbackInterface),
        INVALID_PARAMETERS);
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
        .WillOnce([](int32_t userId, const std::vector<int32_t>& authTypes,
            uint32_t authTrustLevel, std::vector<int32_t>& validTypes) {
            validTypes.clear();
            validTypes.emplace_back(PIN);
            validTypes.emplace_back(FACE);
            return SUCCESS;
        })
        .WillRepeatedly([](int32_t userId, const std::vector<int32_t>& authTypes,
            uint32_t authTrustLevel, std::vector<int32_t>& validTypes) {
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

HWTEST_F(UserAuthServiceTest, UserAuthServiceInsert2ContxtTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    uint64_t testContextId = 123456;
    auto context = Common::MakeShared<MockContext>();
    EXPECT_NE(context, nullptr);
    EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(testContextId));
    EXPECT_CALL(*context, GetLatestError()).WillRepeatedly(Return(GENERAL_ERROR));
    EXPECT_EQ(service->Insert2ContextPool(context), true);
    EXPECT_EQ(service->Insert2ContextPool(context), false);
    EXPECT_TRUE(ContextPool::Instance().Delete(testContextId));
}

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

HWTEST_F(UserAuthServiceTest, UserAuthServiceUpdateTemplateCacheTest, TestSize.Level0)
{
    AuthType testAuthType = FACE;
    TemplateCacheManager::GetInstance().currUserId_ = 100;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _))
        .Times(2)
        .WillOnce([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            infos.clear();
            return HDF_SUCCESS;
        })
        .WillOnce([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 2,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
                .executorMatcher = 2,
                .executorSensorHint = 3
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        });
    EXPECT_NO_THROW(
        TemplateCacheManager::GetInstance().UpdateTemplateCache(FACE);
        TemplateCacheManager::GetInstance().UpdateTemplateCache(FACE);
    );
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

HWTEST_F(UserAuthServiceTest, UserAuthServiceProcessWidgetSessionExTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    int32_t testContextId = 11112;
    ContextType contextType = ContextType::WIDGET_AUTH_CONTEXT;
    auto context = Common::MakeShared<MockContext>();
    EXPECT_NE(context, nullptr);
    EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(testContextId));
    EXPECT_CALL(*context, GetLatestError()).WillRepeatedly(Return(GENERAL_ERROR));
    EXPECT_CALL(*context, GetContextType()).WillRepeatedly(Return(contextType));
    EXPECT_CALL(*context, Stop())
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_EQ(ContextPool::Instance().Insert(context), true);
    EXPECT_NO_THROW(service->ProcessWidgetSessionExclusive());
    EXPECT_EQ(ContextPool::Instance().Delete(testContextId), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceQueryReusableAuthResultTest, TestSize.Level0)
{
    auto service = Common::MakeShared<UserAuthService>();
    IpcAuthParamInner ipcAuthParamInner = {};
    std::vector<uint8_t> token;
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    ipcAuthParamInner.isUserIdSpecified = false;
    ipcAuthParamInner.userId = 110;
    IpcCommon::SetSkipUserFlag(true);
    EXPECT_EQ(service->QueryReusableAuthResult(ipcAuthParamInner, token), GENERAL_ERROR);
    IpcCommon::SetSkipUserFlag(false);
    EXPECT_EQ(service->QueryReusableAuthResult(ipcAuthParamInner, token), GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
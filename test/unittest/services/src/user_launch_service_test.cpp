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

#include "user_auth_service_test.h"

#include <condition_variable>
#include <mutex>

#include "iam_common_defines.h"

#include "mock_ipc_common.h"
#include "mock_launch_service_callback.h"
#include "mock_user_auth_engine.h"
#include "user_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

namespace {
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
} // namespace

/**
 * @tc.name: UserLaunchServiceRegisterLaunchService001
 * @tc.desc: Test RegisterLaunchService with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceRegisterLaunchService001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<IpcLaunchServiceRegisterInfo> serviceList = {};
    sptr<ILaunchServiceListCallback> callback = nullptr;
    int32_t ret = service.RegisterLaunchService(serviceList, callback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

/**
 * @tc.name: UserLaunchServiceRegisterLaunchService002
 * @tc.desc: Test RegisterLaunchService without permission.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceRegisterLaunchService002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<IpcLaunchServiceRegisterInfo> serviceList = {};
    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _)).Times(1);
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    int32_t ret = service.RegisterLaunchService(serviceList, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: UserLaunchServiceRegisterLaunchService003
 * @tc.desc: Test RegisterLaunchService with permission but empty list.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceRegisterLaunchService003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<IpcLaunchServiceRegisterInfo> serviceList = {};
    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, INVALID_PARAMETERS);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.RegisterLaunchService(serviceList, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceRegisterLaunchService004
 * @tc.desc: Test RegisterLaunchService with invalid service info (empty serviceName).
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceRegisterLaunchService004, TestSize.Level0)
{
    UserAuthService service;
    IpcLaunchServiceRegisterInfo info = {};
    info.uid = 100;
    info.serviceKey.serviceName = "";
    info.serviceKey.moduleName = "mod";
    info.serviceInfo.serviceType = static_cast<int32_t>(EngLaunchServiceType::NORMAL_AGENT);
    std::vector<IpcLaunchServiceRegisterInfo> serviceList = {info};

    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, INVALID_PARAMETERS);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.RegisterLaunchService(serviceList, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceRegisterLaunchService005
 * @tc.desc: Test RegisterLaunchService with invalid service info (INVALID serviceType).
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceRegisterLaunchService005, TestSize.Level0)
{
    UserAuthService service;
    IpcLaunchServiceRegisterInfo info = {};
    info.uid = 100;
    info.serviceKey.serviceName = "svc";
    info.serviceKey.moduleName = "mod";
    info.serviceInfo.serviceType = static_cast<int32_t>(EngLaunchServiceType::INVALID);
    std::vector<IpcLaunchServiceRegisterInfo> serviceList = {info};

    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, INVALID_PARAMETERS);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.RegisterLaunchService(serviceList, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceRegisterLaunchService006
 * @tc.desc: Test RegisterLaunchService with valid info and engine success.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceRegisterLaunchService006, TestSize.Level0)
{
    UserAuthService service;
    IpcLaunchServiceRegisterInfo info = {};
    info.uid = 100;
    info.serviceKey.serviceName = "svc";
    info.serviceKey.moduleName = "mod";
    info.serviceInfo.serviceType = static_cast<int32_t>(EngLaunchServiceType::NORMAL_AGENT);
    std::vector<IpcLaunchServiceRegisterInfo> serviceList = {info};

    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, RegisterLaunchService(_, _))
        .WillOnce([](const std::vector<EngLaunchServiceRegisterInfo> &engineList,
            std::vector<EngLaunchServiceFlatInfo> &infos) {
            EngLaunchServiceFlatInfo info = {};
            info.uid = 100;
            info.serviceKey = EngLaunchServiceKey{"svc", "mod"};
            info.activeState = EngLaunchServiceState::INVALID;
            infos.push_back(info);
            return SUCCESS;
        });

    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, SUCCESS);
            EXPECT_EQ(serviceList.size(), 1U);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.RegisterLaunchService(serviceList, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceRegisterLaunchService007
 * @tc.desc: Test RegisterLaunchService with engine failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceRegisterLaunchService007, TestSize.Level0)
{
    UserAuthService service;
    IpcLaunchServiceRegisterInfo info = {};
    info.uid = 100;
    info.serviceKey.serviceName = "svc";
    info.serviceKey.moduleName = "mod";
    info.serviceInfo.serviceType = static_cast<int32_t>(EngLaunchServiceType::NORMAL_AGENT);
    std::vector<IpcLaunchServiceRegisterInfo> serviceList = {info};

    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, RegisterLaunchService(_, _))
        .WillOnce(Return(GENERAL_ERROR));

    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, GENERAL_ERROR);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.RegisterLaunchService(serviceList, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceUnRegisterLaunchService001
 * @tc.desc: Test UnRegisterLaunchService with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceUnRegisterLaunchService001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    sptr<ILaunchServiceCallback> callback = nullptr;
    int32_t ret = service.UnRegisterLaunchService(testUid, false, key, callback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

/**
 * @tc.name: UserLaunchServiceUnRegisterLaunchService002
 * @tc.desc: Test UnRegisterLaunchService without permission.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceUnRegisterLaunchService002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    sptr<MockLaunchServiceCallback> testCallback(new (std::nothrow) MockLaunchServiceCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnLaunchServiceResult(_)).Times(1);
    sptr<ILaunchServiceCallback> callbackInterface = testCallback;
    int32_t ret = service.UnRegisterLaunchService(testUid, false, key, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: UserLaunchServiceUnRegisterLaunchService003
 * @tc.desc: Test UnRegisterLaunchService with key but invalid serviceName.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceUnRegisterLaunchService003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    key.serviceName = "";
    key.moduleName = "mod";
    sptr<MockLaunchServiceCallback> testCallback(new (std::nothrow) MockLaunchServiceCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceResult(_))
        .WillOnce([&sync](int32_t result) {
            EXPECT_EQ(result, INVALID_PARAMETERS);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.UnRegisterLaunchService(testUid, true, key, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceUnRegisterLaunchService004
 * @tc.desc: Test UnRegisterLaunchService without key (hasKey=false) and engine success.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceUnRegisterLaunchService004, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, UnRegisterLaunchService(_, _))
        .WillOnce([](int32_t uid, const std::optional<EngLaunchServiceKey> &key) {
            EXPECT_FALSE(key.has_value());
            return SUCCESS;
        });

    sptr<MockLaunchServiceCallback> testCallback(new (std::nothrow) MockLaunchServiceCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceResult(_))
        .WillOnce([&sync](int32_t result) {
            EXPECT_EQ(result, SUCCESS);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.UnRegisterLaunchService(testUid, false, key, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceUnRegisterLaunchService005
 * @tc.desc: Test UnRegisterLaunchService with key and engine success.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceUnRegisterLaunchService005, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    key.serviceName = "svc";
    key.moduleName = "mod";
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, UnRegisterLaunchService(_, _))
        .WillOnce([](int32_t uid, const std::optional<EngLaunchServiceKey> &key) {
            EXPECT_TRUE(key.has_value());
            return SUCCESS;
        });

    sptr<MockLaunchServiceCallback> testCallback(new (std::nothrow) MockLaunchServiceCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceResult(_))
        .WillOnce([&sync](int32_t result) {
            EXPECT_EQ(result, SUCCESS);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.UnRegisterLaunchService(testUid, true, key, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceInfo001
 * @tc.desc: Test GetLaunchServiceInfo with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceInfo001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    sptr<ILaunchServiceListCallback> callback = nullptr;
    int32_t ret = service.GetLaunchServiceInfo(testUid, false, key, callback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceInfo002
 * @tc.desc: Test GetLaunchServiceInfo without permission.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceInfo002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _)).Times(1);
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    int32_t ret = service.GetLaunchServiceInfo(testUid, false, key, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceInfo003
 * @tc.desc: Test GetLaunchServiceInfo with invalid key (empty serviceName).
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceInfo003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    key.serviceName = "";
    key.moduleName = "mod";
    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, INVALID_PARAMETERS);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.GetLaunchServiceInfo(testUid, true, key, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceInfo004
 * @tc.desc: Test GetLaunchServiceInfo without key and engine success.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceInfo004, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, GetLaunchServiceInfo(_, _, _))
        .WillOnce([](int32_t uid, const std::optional<EngLaunchServiceKey> &key,
            std::vector<EngLaunchServiceFlatInfo> &serviceList) {
            EngLaunchServiceFlatInfo info = {};
            info.uid = uid;
            serviceList.push_back(info);
            return SUCCESS;
        });

    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, SUCCESS);
            EXPECT_EQ(serviceList.size(), 1U);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.GetLaunchServiceInfo(testUid, false, key, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceInfo005
 * @tc.desc: Test GetLaunchServiceInfo with engine failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceInfo005, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    IpcLaunchServiceKey key = {};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, GetLaunchServiceInfo(_, _, _))
        .WillOnce(Return(GENERAL_ERROR));

    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, GENERAL_ERROR);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.GetLaunchServiceInfo(testUid, false, key, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceList001
 * @tc.desc: Test GetLaunchServiceList with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceList001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    sptr<ILaunchServiceListCallback> callback = nullptr;
    int32_t ret = service.GetLaunchServiceList(true, testUserId, callback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceList002
 * @tc.desc: Test GetLaunchServiceList without permission.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceList002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _)).Times(1);
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    int32_t ret = service.GetLaunchServiceList(true, testUserId, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceList003
 * @tc.desc: Test GetLaunchServiceList with userId and engine success.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceList003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, GetLaunchServiceList(_, _))
        .WillOnce([](const std::vector<int32_t> &userIds,
            std::vector<EngLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(userIds.size(), 1U);
            EngLaunchServiceFlatInfo info = {};
            serviceList.push_back(info);
            return SUCCESS;
        });

    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, SUCCESS);
            EXPECT_EQ(serviceList.size(), 1U);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.GetLaunchServiceList(true, testUserId, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceList004
 * @tc.desc: Test GetLaunchServiceList without userId (gets all users).
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceList004, TestSize.Level0)
{
    UserAuthService service;
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, GetLaunchServiceList(_, _))
        .WillRepeatedly([](const std::vector<int32_t> &userIds,
            std::vector<EngLaunchServiceFlatInfo> &serviceList) {
            return SUCCESS;
        });

    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    IpcCommon::SetSkipCallerFlag(false);
    int32_t ret = service.GetLaunchServiceList(false, 0, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceList005
 * @tc.desc: Test GetLaunchServiceList without userId and GetAllUserId fails.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceList005, TestSize.Level0)
{
    UserAuthService service;
    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, IPC_ERROR);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    IpcCommon::SetSkipCallerFlag(true);
    int32_t ret = service.GetLaunchServiceList(false, 0, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
    IpcCommon::SetSkipCallerFlag(false);
}

/**
 * @tc.name: UserLaunchServiceGetLaunchServiceList006
 * @tc.desc: Test GetLaunchServiceList with engine failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceGetLaunchServiceList006, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, GetLaunchServiceList(_, _))
        .WillOnce(Return(GENERAL_ERROR));

    sptr<MockLaunchServiceListCallback> testCallback(new (std::nothrow) MockLaunchServiceListCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceListResult(_, _))
        .WillOnce([&sync](int32_t result, const std::vector<IpcLaunchServiceFlatInfo> &serviceList) {
            EXPECT_EQ(result, GENERAL_ERROR);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceListCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    int32_t ret = service.GetLaunchServiceList(true, testUserId, callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
}

/**
 * @tc.name: UserLaunchServiceSetLaunchServiceState001
 * @tc.desc: Test SetLaunchServiceState with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetLaunchServiceState001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    std::vector<uint8_t> testToken = {1, 2, 3};
    sptr<ILaunchServiceCallback> callback = nullptr;
    int32_t ret = service.SetLaunchServiceState(testUid, testToken,
        static_cast<int32_t>(EngLaunchServiceState::AGENT_ACTIVE), callback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

/**
 * @tc.name: UserLaunchServiceSetLaunchServiceState002
 * @tc.desc: Test SetLaunchServiceState without permission.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetLaunchServiceState002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    std::vector<uint8_t> testToken = {1, 2, 3};
    sptr<MockLaunchServiceCallback> testCallback(new (std::nothrow) MockLaunchServiceCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnLaunchServiceResult(_)).Times(1);
    sptr<ILaunchServiceCallback> callbackInterface = testCallback;
    int32_t ret = service.SetLaunchServiceState(testUid, testToken,
        static_cast<int32_t>(EngLaunchServiceState::AGENT_ACTIVE), callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: UserLaunchServiceSetLaunchServiceState003
 * @tc.desc: Test SetLaunchServiceState with permission and non-empty token, engine success.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetLaunchServiceState003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    std::vector<uint8_t> testToken = {1, 2, 3};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, SetLaunchServiceState(_, _, _))
        .WillOnce([](int32_t uid, const std::vector<uint8_t> &token, EngLaunchServiceState state) {
            return SUCCESS;
        });

    sptr<MockLaunchServiceCallback> testCallback(new (std::nothrow) MockLaunchServiceCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceResult(_))
        .WillOnce([&sync](int32_t result) {
            EXPECT_EQ(result, SUCCESS);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    IpcCommon::SetSkipCallerFlag(true);
    int32_t ret = service.SetLaunchServiceState(testUid, testToken,
        static_cast<int32_t>(EngLaunchServiceState::AGENT_ACTIVE), callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
    IpcCommon::SetSkipCallerFlag(false);
}

/**
 * @tc.name: UserLaunchServiceSetLaunchServiceState004
 * @tc.desc: Test SetLaunchServiceState with empty token, GetAppLaunchServiceType fails.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetLaunchServiceState004, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    std::vector<uint8_t> emptyToken = {};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, GetAppLaunchServiceType(_, _))
        .WillOnce(Return(GENERAL_ERROR));

    sptr<MockLaunchServiceCallback> testCallback(new (std::nothrow) MockLaunchServiceCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceResult(_))
        .WillOnce([&sync](int32_t result) {
            EXPECT_EQ(result, GENERAL_ERROR);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    IpcCommon::SetSkipCallerFlag(true);
    int32_t ret = service.SetLaunchServiceState(testUid, emptyToken,
        static_cast<int32_t>(EngLaunchServiceState::AGENT_ACTIVE), callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
    IpcCommon::SetSkipCallerFlag(false);
}

/**
 * @tc.name: UserLaunchServiceSetLaunchServiceState005
 * @tc.desc: Test SetLaunchServiceState with non-empty token and engine failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetLaunchServiceState005, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUid = 100;
    std::vector<uint8_t> testToken = {1, 2, 3};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, SetLaunchServiceState(_, _, _))
        .WillOnce(Return(GENERAL_ERROR));

    sptr<MockLaunchServiceCallback> testCallback(new (std::nothrow) MockLaunchServiceCallback());
    EXPECT_NE(testCallback, nullptr);
    SimpleSync sync;
    EXPECT_CALL(*testCallback, OnLaunchServiceResult(_))
        .WillOnce([&sync](int32_t result) {
            EXPECT_EQ(result, GENERAL_ERROR);
            sync.Notify();
            return SUCCESS;
        });
    sptr<ILaunchServiceCallback> callbackInterface = testCallback;
    ScopedPermission perm(USE_USER_ACCESS_MANAGER);
    IpcCommon::SetSkipCallerFlag(true);
    int32_t ret = service.SetLaunchServiceState(testUid, testToken,
        static_cast<int32_t>(EngLaunchServiceState::INVALID), callbackInterface);
    EXPECT_EQ(ret, SUCCESS);
    sync.Wait();
    IpcCommon::SetSkipCallerFlag(false);
}

/**
 * @tc.name: UserLaunchServiceSetDaemonAllowedlist001
 * @tc.desc: Test SetDaemonAllowedlist without permission.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetDaemonAllowedlist001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1"};
    int32_t funcRet = SUCCESS;
    int32_t ret = service.SetDaemonAllowedlist(testUserId, testAppIdentifiers, true, funcRet);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(funcRet, CHECK_PERMISSION_FAILED);
}

/**
 * @tc.name: UserLaunchServiceSetDaemonAllowedlist002
 * @tc.desc: Test SetDaemonAllowedlist with permission and engine success.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetDaemonAllowedlist002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1", "app2"};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, SetDaemonAllowedlist(_, _, _))
        .WillOnce([](int32_t userId, const std::vector<std::string> &appIdentifiers, bool isAdd) {
            return SUCCESS;
        });

    int32_t funcRet = GENERAL_ERROR;
    ScopedPermission perm(ENTERPRISE_DEVICE_MGR);
    int32_t ret = service.SetDaemonAllowedlist(testUserId, testAppIdentifiers, true, funcRet);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(funcRet, SUCCESS);
}

/**
 * @tc.name: UserLaunchServiceSetDaemonAllowedlist003
 * @tc.desc: Test SetDaemonAllowedlist with engine failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetDaemonAllowedlist003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1"};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, SetDaemonAllowedlist(_, _, _))
        .WillOnce(Return(GENERAL_ERROR));

    int32_t funcRet = SUCCESS;
    ScopedPermission perm(ENTERPRISE_DEVICE_MGR);
    int32_t ret = service.SetDaemonAllowedlist(testUserId, testAppIdentifiers, false, funcRet);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(funcRet, GENERAL_ERROR);
}

/**
 * @tc.name: UserLaunchServiceSetDaemonForbiddenlist001
 * @tc.desc: Test SetDaemonForbiddenlist without permission.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetDaemonForbiddenlist001, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1"};
    int32_t funcRet = SUCCESS;
    int32_t ret = service.SetDaemonForbiddenlist(testUserId, testAppIdentifiers, true, funcRet);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(funcRet, CHECK_PERMISSION_FAILED);
}

/**
 * @tc.name: UserLaunchServiceSetDaemonForbiddenlist002
 * @tc.desc: Test SetDaemonForbiddenlist with permission and engine success.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetDaemonForbiddenlist002, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1", "app2"};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, SetDaemonForbiddenlist(_, _, _))
        .WillOnce([](int32_t userId, const std::vector<std::string> &appIdentifiers, bool isAdd) {
            return SUCCESS;
        });

    int32_t funcRet = GENERAL_ERROR;
    ScopedPermission perm(ENTERPRISE_DEVICE_MGR);
    int32_t ret = service.SetDaemonForbiddenlist(testUserId, testAppIdentifiers, false, funcRet);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(funcRet, SUCCESS);
}

/**
 * @tc.name: UserLaunchServiceSetDaemonForbiddenlist003
 * @tc.desc: Test SetDaemonForbiddenlist with engine failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceSetDaemonForbiddenlist003, TestSize.Level0)
{
    UserAuthService service;
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1"};
    auto mockEngine = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockEngine, nullptr);
    EXPECT_CALL(*mockEngine, SetDaemonForbiddenlist(_, _, _))
        .WillOnce(Return(GENERAL_ERROR));

    int32_t funcRet = SUCCESS;
    ScopedPermission perm(ENTERPRISE_DEVICE_MGR);
    int32_t ret = service.SetDaemonForbiddenlist(testUserId, testAppIdentifiers, true, funcRet);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(funcRet, GENERAL_ERROR);
}

/**
 * @tc.name: UserLaunchServiceConvertToIpcLaunchServiceFlatInfo001
 * @tc.desc: Test ConvertToIpcLaunchServiceFlatInfo static helper.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceConvertToIpcLaunchServiceFlatInfo001, TestSize.Level0)
{
    EngLaunchServiceFlatInfo info = {};
    info.uid = 100;
    info.serviceKey = EngLaunchServiceKey{"svc", "mod"};
    info.bundleInfo = EngBundleExtInfo{"com.test", 1, "id123"};
    info.serviceInfo = EngServiceExtInfo{EngLaunchServiceType::NORMAL_AGENT, "extra"};
    info.activeState = EngLaunchServiceState::AGENT_ACTIVE;
    info.isForbidden = true;
    info.launchServiceSize = 5;

    IpcLaunchServiceFlatInfo ipcInfo = UserAuthService::ConvertToIpcLaunchServiceFlatInfo(info);
    EXPECT_EQ(ipcInfo.uid, info.uid);
    EXPECT_EQ(ipcInfo.serviceKey.serviceName, info.serviceKey.serviceName);
    EXPECT_EQ(ipcInfo.serviceKey.moduleName, info.serviceKey.moduleName);
    EXPECT_EQ(ipcInfo.bundleInfo.ownerBundleName, info.bundleInfo.ownerBundleName);
    EXPECT_EQ(ipcInfo.bundleInfo.appIndex, info.bundleInfo.appIndex);
    EXPECT_EQ(ipcInfo.bundleInfo.appIdentifier, info.bundleInfo.appIdentifier);
    EXPECT_EQ(ipcInfo.serviceInfo.serviceType, static_cast<int32_t>(info.serviceInfo.serviceType));
    EXPECT_EQ(ipcInfo.serviceInfo.additionalInfo, info.serviceInfo.additionalInfo);
    EXPECT_EQ(ipcInfo.activeState, static_cast<int32_t>(info.activeState));
    EXPECT_EQ(ipcInfo.isForbidden, info.isForbidden);
    EXPECT_EQ(ipcInfo.launchServiceSize, info.launchServiceSize);
}

/**
 * @tc.name: UserLaunchServiceConvertFromIpcLaunchServiceRegisterInfo001
 * @tc.desc: Test ConvertFromIpcLaunchServiceRegisterInfo static helper.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthServiceTest, UserLaunchServiceConvertFromIpcLaunchServiceRegisterInfo001, TestSize.Level0)
{
    IpcLaunchServiceRegisterInfo ipcInfo = {};
    ipcInfo.uid = 200;
    ipcInfo.serviceKey = IpcLaunchServiceKey{"svc", "mod"};
    ipcInfo.bundleInfo = IpcBundleExtInfo{"com.test", 2, "id456"};
    ipcInfo.serviceInfo = IpcServiceExtInfo{static_cast<int32_t>(EngLaunchServiceType::PRIVILEGED_DAEMON), "data"};

    EngLaunchServiceRegisterInfo info = UserAuthService::ConvertFromIpcLaunchServiceRegisterInfo(ipcInfo);
    EXPECT_EQ(info.uid, ipcInfo.uid);
    EXPECT_EQ(info.serviceKey.serviceName, ipcInfo.serviceKey.serviceName);
    EXPECT_EQ(info.serviceKey.moduleName, ipcInfo.serviceKey.moduleName);
    EXPECT_EQ(info.bundleInfo.ownerBundleName, ipcInfo.bundleInfo.ownerBundleName);
    EXPECT_EQ(info.bundleInfo.appIndex, ipcInfo.bundleInfo.appIndex);
    EXPECT_EQ(info.bundleInfo.appIdentifier, ipcInfo.bundleInfo.appIdentifier);
    EXPECT_EQ(static_cast<int32_t>(info.serviceInfo.serviceType), ipcInfo.serviceInfo.serviceType);
    EXPECT_EQ(info.serviceInfo.additionalInfo, ipcInfo.serviceInfo.additionalInfo);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

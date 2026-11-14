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

#include "user_launch_service_client_test.h"

#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "user_launch_service_client.h"
#include "user_launch_service_client_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserLaunchServiceClientTest::SetUpTestCase()
{
}

void UserLaunchServiceClientTest::TearDownTestCase()
{
}

void UserLaunchServiceClientTest::SetUp()
{
}

void UserLaunchServiceClientTest::TearDown()
{
    IpcClientUtils::ResetObj();
}

void UserLaunchServiceClientTest::CallRemoteObject(const std::shared_ptr<MockUserAuthService> service,
    const sptr<MockRemoteObject> &obj, sptr<IRemoteObject::DeathRecipient> &dr, uint32_t sendRequestTimes)
{
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillRepeatedly([&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
            dr = recipient;
            return true;
        });

    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(sendRequestTimes);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
}

/**
 * @tc.name: UserLaunchServiceClientRegisterLaunchService001
 * @tc.desc: Test RegisterLaunchService with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientRegisterLaunchService001, TestSize.Level0)
{
    std::vector<LaunchServiceRegisterInfo> serviceList = {};
    std::shared_ptr<MockLaunchServiceListCallback> testCallback = nullptr;
    // nullptr callback: no crash, no IPC
    UserLaunchServiceClient::GetInstance().RegisterLaunchService(serviceList, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientRegisterLaunchService002
 * @tc.desc: Test RegisterLaunchService without proxy (GetProxy returns nullptr).
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientRegisterLaunchService002, TestSize.Level0)
{
    std::vector<LaunchServiceRegisterInfo> serviceList = {};
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcClientUtils::ResetObj();
    UserLaunchServiceClient::GetInstance().RegisterLaunchService(serviceList, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientRegisterLaunchService003
 * @tc.desc: Test RegisterLaunchService with valid proxy and SUCCESS return.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientRegisterLaunchService003, TestSize.Level0)
{
    LaunchServiceRegisterInfo info = {};
    info.uid = 100;
    info.serviceKey.serviceName = "test_service";
    info.serviceKey.moduleName = "test_module";
    info.bundleInfo.ownerBundleName = "com.test";
    info.bundleInfo.appIndex = 0;
    info.bundleInfo.appIdentifier = "test_id";
    info.serviceInfo.serviceType = LaunchServiceType::NORMAL_AGENT;
    info.serviceInfo.additionalInfo = "extra";
    std::vector<LaunchServiceRegisterInfo> serviceList = {info};

    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterLaunchService(_, _)).Times(1);
    ON_CALL(*service, RegisterLaunchService)
        .WillByDefault(Invoke(
            [&serviceList](const std::vector<IpcLaunchServiceRegisterInfo> &ipcList,
                const sptr<ILaunchServiceListCallback> &callback) -> int32_t {
                EXPECT_EQ(ipcList.size(), serviceList.size());
                if (callback != nullptr) {
                    callback->OnLaunchServiceListResult(SUCCESS, std::vector<IpcLaunchServiceFlatInfo>{});
                }
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().RegisterLaunchService(serviceList, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientRegisterLaunchService004
 * @tc.desc: Test RegisterLaunchService when IPC call returns failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientRegisterLaunchService004, TestSize.Level0)
{
    std::vector<LaunchServiceRegisterInfo> serviceList = {};
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterLaunchService(_, _)).Times(1);
    ON_CALL(*service, RegisterLaunchService)
        .WillByDefault(Invoke([](const std::vector<IpcLaunchServiceRegisterInfo> &ipcList,
            const sptr<ILaunchServiceListCallback> &callback) -> int32_t {
            return GENERAL_ERROR;
        }));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().RegisterLaunchService(serviceList, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientUnRegisterLaunchService001
 * @tc.desc: Test UnRegisterLaunchService with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientUnRegisterLaunchService001, TestSize.Level0)
{
    int32_t testUid = 100;
    std::optional<LaunchServiceKey> testKey = std::nullopt;
    std::shared_ptr<MockLaunchServiceCallback> testCallback = nullptr;
    UserLaunchServiceClient::GetInstance().UnRegisterLaunchService(testUid, testKey, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientUnRegisterLaunchService002
 * @tc.desc: Test UnRegisterLaunchService without proxy.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientUnRegisterLaunchService002, TestSize.Level0)
{
    int32_t testUid = 100;
    std::optional<LaunchServiceKey> testKey = std::nullopt;
    auto testCallback = Common::MakeShared<MockLaunchServiceCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_)).Times(1);
    IpcClientUtils::ResetObj();
    UserLaunchServiceClient::GetInstance().UnRegisterLaunchService(testUid, testKey, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientUnRegisterLaunchService003
 * @tc.desc: Test UnRegisterLaunchService with valid proxy and key.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientUnRegisterLaunchService003, TestSize.Level0)
{
    int32_t testUid = 100;
    LaunchServiceKey key = {"svc", "mod"};
    std::optional<LaunchServiceKey> testKey = key;
    auto testCallback = Common::MakeShared<MockLaunchServiceCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnRegisterLaunchService(_, _, _, _)).Times(1);
    ON_CALL(*service, UnRegisterLaunchService)
        .WillByDefault(Invoke(
            [&testUid, &key](int32_t uid, bool hasKey, const IpcLaunchServiceKey &ipcKey,
                const sptr<ILaunchServiceCallback> &callback) -> int32_t {
                EXPECT_EQ(uid, testUid);
                EXPECT_TRUE(hasKey);
                EXPECT_EQ(ipcKey.serviceName, key.serviceName);
                EXPECT_EQ(ipcKey.moduleName, key.moduleName);
                if (callback != nullptr) {
                    callback->OnLaunchServiceResult(SUCCESS);
                }
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().UnRegisterLaunchService(testUid, testKey, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientUnRegisterLaunchService004
 * @tc.desc: Test UnRegisterLaunchService without key (hasKey=false).
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientUnRegisterLaunchService004, TestSize.Level0)
{
    int32_t testUid = 100;
    std::optional<LaunchServiceKey> testKey = std::nullopt;
    auto testCallback = Common::MakeShared<MockLaunchServiceCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnRegisterLaunchService(_, _, _, _)).Times(1);
    ON_CALL(*service, UnRegisterLaunchService)
        .WillByDefault(Invoke(
            [&testUid](int32_t uid, bool hasKey, const IpcLaunchServiceKey &ipcKey,
                const sptr<ILaunchServiceCallback> &callback) -> int32_t {
                EXPECT_EQ(uid, testUid);
                EXPECT_FALSE(hasKey);
                if (callback != nullptr) {
                    callback->OnLaunchServiceResult(SUCCESS);
                }
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().UnRegisterLaunchService(testUid, testKey, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientUnRegisterLaunchService005
 * @tc.desc: Test UnRegisterLaunchService when IPC returns failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientUnRegisterLaunchService005, TestSize.Level0)
{
    int32_t testUid = 100;
    std::optional<LaunchServiceKey> testKey = std::nullopt;
    auto testCallback = Common::MakeShared<MockLaunchServiceCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_)).Times(1);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnRegisterLaunchService(_, _, _, _)).Times(1);
    ON_CALL(*service, UnRegisterLaunchService)
        .WillByDefault(Invoke([](int32_t uid, bool hasKey, const IpcLaunchServiceKey &ipcKey,
            const sptr<ILaunchServiceCallback> &callback) -> int32_t {
            return GENERAL_ERROR;
        }));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().UnRegisterLaunchService(testUid, testKey, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceInfo001
 * @tc.desc: Test GetLaunchServiceInfo with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceInfo001, TestSize.Level0)
{
    int32_t testUid = 100;
    std::optional<LaunchServiceKey> testKey = std::nullopt;
    std::shared_ptr<MockLaunchServiceListCallback> testCallback = nullptr;
    UserLaunchServiceClient::GetInstance().GetLaunchServiceInfo(testUid, testKey, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceInfo002
 * @tc.desc: Test GetLaunchServiceInfo without proxy.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceInfo002, TestSize.Level0)
{
    int32_t testUid = 100;
    std::optional<LaunchServiceKey> testKey = std::nullopt;
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcClientUtils::ResetObj();
    UserLaunchServiceClient::GetInstance().GetLaunchServiceInfo(testUid, testKey, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceInfo003
 * @tc.desc: Test GetLaunchServiceInfo with valid proxy and key.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceInfo003, TestSize.Level0)
{
    int32_t testUid = 100;
    LaunchServiceKey key = {"svc", "mod"};
    std::optional<LaunchServiceKey> testKey = key;
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetLaunchServiceInfo(_, _, _, _)).Times(1);
    ON_CALL(*service, GetLaunchServiceInfo)
        .WillByDefault(Invoke(
            [&testUid, &key](int32_t uid, bool hasKey, const IpcLaunchServiceKey &ipcKey,
                const sptr<ILaunchServiceListCallback> &callback) -> int32_t {
                EXPECT_EQ(uid, testUid);
                EXPECT_TRUE(hasKey);
                EXPECT_EQ(ipcKey.serviceName, key.serviceName);
                EXPECT_EQ(ipcKey.moduleName, key.moduleName);
                if (callback != nullptr) {
                    IpcLaunchServiceFlatInfo info = {};
                    info.uid = testUid;
                    info.serviceKey = IpcLaunchServiceKey{key.serviceName, key.moduleName};
                    callback->OnLaunchServiceListResult(SUCCESS, {info});
                }
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().GetLaunchServiceInfo(testUid, testKey, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceInfo004
 * @tc.desc: Test GetLaunchServiceInfo without key.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceInfo004, TestSize.Level0)
{
    int32_t testUid = 100;
    std::optional<LaunchServiceKey> testKey = std::nullopt;
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetLaunchServiceInfo(_, _, _, _)).Times(1);
    ON_CALL(*service, GetLaunchServiceInfo)
        .WillByDefault(Invoke(
            [&testUid](int32_t uid, bool hasKey, const IpcLaunchServiceKey &ipcKey,
                const sptr<ILaunchServiceListCallback> &callback) -> int32_t {
                EXPECT_EQ(uid, testUid);
                EXPECT_FALSE(hasKey);
                if (callback != nullptr) {
                    callback->OnLaunchServiceListResult(SUCCESS, std::vector<IpcLaunchServiceFlatInfo>{});
                }
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().GetLaunchServiceInfo(testUid, testKey, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceInfo005
 * @tc.desc: Test GetLaunchServiceInfo when IPC returns failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceInfo005, TestSize.Level0)
{
    int32_t testUid = 100;
    std::optional<LaunchServiceKey> testKey = std::nullopt;
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetLaunchServiceInfo(_, _, _, _)).Times(1);
    ON_CALL(*service, GetLaunchServiceInfo)
        .WillByDefault(Invoke([](int32_t uid, bool hasKey, const IpcLaunchServiceKey &ipcKey,
            const sptr<ILaunchServiceListCallback> &callback) -> int32_t {
            return GENERAL_ERROR;
        }));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().GetLaunchServiceInfo(testUid, testKey, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceList001
 * @tc.desc: Test GetLaunchServiceList with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceList001, TestSize.Level0)
{
    std::optional<int32_t> testUserId = std::nullopt;
    std::shared_ptr<MockLaunchServiceListCallback> testCallback = nullptr;
    UserLaunchServiceClient::GetInstance().GetLaunchServiceList(testUserId, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceList002
 * @tc.desc: Test GetLaunchServiceList without proxy.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceList002, TestSize.Level0)
{
    std::optional<int32_t> testUserId = std::nullopt;
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcClientUtils::ResetObj();
    UserLaunchServiceClient::GetInstance().GetLaunchServiceList(testUserId, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceList003
 * @tc.desc: Test GetLaunchServiceList with userId.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceList003, TestSize.Level0)
{
    int32_t userId = 100;
    std::optional<int32_t> testUserId = userId;
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetLaunchServiceList(_, _, _)).Times(1);
    ON_CALL(*service, GetLaunchServiceList)
        .WillByDefault(Invoke(
            [&userId](bool hasUserId, int32_t ipcUserId,
                const sptr<ILaunchServiceListCallback> &callback) -> int32_t {
                EXPECT_TRUE(hasUserId);
                EXPECT_EQ(ipcUserId, userId);
                if (callback != nullptr) {
                    callback->OnLaunchServiceListResult(SUCCESS, std::vector<IpcLaunchServiceFlatInfo>{});
                }
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().GetLaunchServiceList(testUserId, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceList004
 * @tc.desc: Test GetLaunchServiceList without userId.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceList004, TestSize.Level0)
{
    std::optional<int32_t> testUserId = std::nullopt;
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetLaunchServiceList(_, _, _)).Times(1);
    ON_CALL(*service, GetLaunchServiceList)
        .WillByDefault(Invoke(
            [](bool hasUserId, int32_t ipcUserId,
                const sptr<ILaunchServiceListCallback> &callback) -> int32_t {
                EXPECT_FALSE(hasUserId);
                if (callback != nullptr) {
                    callback->OnLaunchServiceListResult(SUCCESS, std::vector<IpcLaunchServiceFlatInfo>{});
                }
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().GetLaunchServiceList(testUserId, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientGetLaunchServiceList005
 * @tc.desc: Test GetLaunchServiceList when IPC returns failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientGetLaunchServiceList005, TestSize.Level0)
{
    std::optional<int32_t> testUserId = std::nullopt;
    auto testCallback = Common::MakeShared<MockLaunchServiceListCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetLaunchServiceList(_, _, _)).Times(1);
    ON_CALL(*service, GetLaunchServiceList)
        .WillByDefault(Invoke([](bool hasUserId, int32_t ipcUserId,
            const sptr<ILaunchServiceListCallback> &callback) -> int32_t {
            return GENERAL_ERROR;
        }));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().GetLaunchServiceList(testUserId, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientSetLaunchServiceState001
 * @tc.desc: Test SetLaunchServiceState with nullptr callback.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetLaunchServiceState001, TestSize.Level0)
{
    int32_t testUid = 100;
    std::vector<uint8_t> testToken = {1, 2, 3};
    LaunchServiceState testState = LaunchServiceState::ACTIVATE;
    std::shared_ptr<MockLaunchServiceCallback> testCallback = nullptr;
    UserLaunchServiceClient::GetInstance().SetLaunchServiceState(testUid, testToken, testState, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientSetLaunchServiceState002
 * @tc.desc: Test SetLaunchServiceState without proxy.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetLaunchServiceState002, TestSize.Level0)
{
    int32_t testUid = 100;
    std::vector<uint8_t> testToken = {1, 2, 3};
    LaunchServiceState testState = LaunchServiceState::ACTIVATE;
    auto testCallback = Common::MakeShared<MockLaunchServiceCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_)).Times(1);
    IpcClientUtils::ResetObj();
    UserLaunchServiceClient::GetInstance().SetLaunchServiceState(testUid, testToken, testState, testCallback);
}

/**
 * @tc.name: UserLaunchServiceClientSetLaunchServiceState003
 * @tc.desc: Test SetLaunchServiceState with valid proxy.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetLaunchServiceState003, TestSize.Level0)
{
    int32_t testUid = 100;
    std::vector<uint8_t> testToken = {1, 2, 3};
    LaunchServiceState testState = LaunchServiceState::ACTIVATE;
    auto testCallback = Common::MakeShared<MockLaunchServiceCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetLaunchServiceState(_, _, _, _)).Times(1);
    ON_CALL(*service, SetLaunchServiceState)
        .WillByDefault(Invoke(
            [&testUid, &testToken, &testState](int32_t uid, const std::vector<uint8_t> &token, int32_t activeState,
                const sptr<ILaunchServiceCallback> &callback) -> int32_t {
                EXPECT_EQ(uid, testUid);
                EXPECT_THAT(token, ElementsAreArray(testToken));
                EXPECT_EQ(activeState, static_cast<int32_t>(testState));
                if (callback != nullptr) {
                    callback->OnLaunchServiceResult(SUCCESS);
                }
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().SetLaunchServiceState(testUid, testToken, testState, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientSetLaunchServiceState004
 * @tc.desc: Test SetLaunchServiceState when IPC returns failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetLaunchServiceState004, TestSize.Level0)
{
    int32_t testUid = 100;
    std::vector<uint8_t> testToken = {1, 2, 3};
    LaunchServiceState testState = LaunchServiceState::ACTIVATE;
    auto testCallback = Common::MakeShared<MockLaunchServiceCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_)).Times(1);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetLaunchServiceState(_, _, _, _)).Times(1);
    ON_CALL(*service, SetLaunchServiceState)
        .WillByDefault(Invoke([](int32_t uid, const std::vector<uint8_t> &token, int32_t activeState,
            const sptr<ILaunchServiceCallback> &callback) -> int32_t {
            return GENERAL_ERROR;
        }));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserLaunchServiceClient::GetInstance().SetLaunchServiceState(testUid, testToken, testState, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientSetDaemonAllowedlist001
 * @tc.desc: Test SetDaemonAllowedlist without proxy.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetDaemonAllowedlist001, TestSize.Level0)
{
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1", "app2"};
    IpcClientUtils::ResetObj();
    int32_t ret = UserLaunchServiceClient::GetInstance().SetDaemonAllowedlist(testUserId, testAppIdentifiers, true);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

/**
 * @tc.name: UserLaunchServiceClientSetDaemonAllowedlist002
 * @tc.desc: Test SetDaemonAllowedlist with valid proxy.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetDaemonAllowedlist002, TestSize.Level0)
{
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1", "app2"};
    bool testIsAdd = true;
    int32_t testFuncRet = SUCCESS;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetDaemonAllowedlist(_, _, _, _)).Times(1);
    ON_CALL(*service, SetDaemonAllowedlist)
        .WillByDefault(Invoke(
            [&testUserId, &testAppIdentifiers, &testIsAdd, &testFuncRet](int32_t userId,
                const std::vector<std::string> &appIdentifiers, bool isAdd, int32_t &funcRet) -> int32_t {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(appIdentifiers, testAppIdentifiers);
                EXPECT_EQ(isAdd, testIsAdd);
                funcRet = testFuncRet;
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    int32_t ret = UserLaunchServiceClient::GetInstance().SetDaemonAllowedlist(testUserId, testAppIdentifiers,
        testIsAdd);
    EXPECT_EQ(ret, testFuncRet);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientSetDaemonAllowedlist003
 * @tc.desc: Test SetDaemonAllowedlist when IPC returns failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetDaemonAllowedlist003, TestSize.Level0)
{
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1"};

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetDaemonAllowedlist(_, _, _, _)).Times(1);
    ON_CALL(*service, SetDaemonAllowedlist)
        .WillByDefault(Invoke([](int32_t userId, const std::vector<std::string> &appIdentifiers, bool isAdd,
            int32_t &funcRet) -> int32_t {
            return GENERAL_ERROR;
        }));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    int32_t ret = UserLaunchServiceClient::GetInstance().SetDaemonAllowedlist(testUserId, testAppIdentifiers, true);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientSetDaemonForbiddenlist001
 * @tc.desc: Test SetDaemonForbiddenlist without proxy.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetDaemonForbiddenlist001, TestSize.Level0)
{
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1", "app2"};
    IpcClientUtils::ResetObj();
    int32_t ret = UserLaunchServiceClient::GetInstance().SetDaemonForbiddenlist(testUserId, testAppIdentifiers,
        false);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

/**
 * @tc.name: UserLaunchServiceClientSetDaemonForbiddenlist002
 * @tc.desc: Test SetDaemonForbiddenlist with valid proxy.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetDaemonForbiddenlist002, TestSize.Level0)
{
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1", "app2"};
    bool testIsAdd = false;
    int32_t testFuncRet = SUCCESS;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetDaemonForbiddenlist(_, _, _, _)).Times(1);
    ON_CALL(*service, SetDaemonForbiddenlist)
        .WillByDefault(Invoke(
            [&testUserId, &testAppIdentifiers, &testIsAdd, &testFuncRet](int32_t userId,
                const std::vector<std::string> &appIdentifiers, bool isAdd, int32_t &funcRet) -> int32_t {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(appIdentifiers, testAppIdentifiers);
                EXPECT_EQ(isAdd, testIsAdd);
                funcRet = testFuncRet;
                return SUCCESS;
            }
        ));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    int32_t ret = UserLaunchServiceClient::GetInstance().SetDaemonForbiddenlist(testUserId, testAppIdentifiers,
        testIsAdd);
    EXPECT_EQ(ret, testFuncRet);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

/**
 * @tc.name: UserLaunchServiceClientSetDaemonForbiddenlist003
 * @tc.desc: Test SetDaemonForbiddenlist when IPC returns failure.
 * @tc.type: FUNC
 */
HWTEST_F(UserLaunchServiceClientTest, UserLaunchServiceClientSetDaemonForbiddenlist003, TestSize.Level0)
{
    int32_t testUserId = 100;
    std::vector<std::string> testAppIdentifiers = {"app1"};

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetDaemonForbiddenlist(_, _, _, _)).Times(1);
    ON_CALL(*service, SetDaemonForbiddenlist)
        .WillByDefault(Invoke([](int32_t userId, const std::vector<std::string> &appIdentifiers, bool isAdd,
            int32_t &funcRet) -> int32_t {
            return GENERAL_ERROR;
        }));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    int32_t ret = UserLaunchServiceClient::GetInstance().SetDaemonForbiddenlist(testUserId, testAppIdentifiers,
        false);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

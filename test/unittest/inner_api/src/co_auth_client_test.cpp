/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "co_auth_client_test.h"

#include "co_auth_client.h"
#include "iam_ptr.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void CoAuthClientTest::SetUpTestCase()
{
}

void CoAuthClientTest::TearDownTestCase()
{
}

void CoAuthClientTest::SetUp()
{
}

void CoAuthClientTest::TearDown()
{
    IpcClientUtils::ResetObj();
}

HWTEST_F(CoAuthClientTest, CoAuthClientRegister_001, TestSize.Level0)
{
    ExecutorInfo testInfo = {};
    std::shared_ptr<ExecutorRegisterCallback> testCallback = nullptr;

    CoAuthClient::GetInstance().Register(testInfo, testCallback);

    testInfo.authType = PIN;
    testInfo.executorRole = COLLECTOR;
    testInfo.executorSensorHint = 11;
    testInfo.executorMatcher = 22;
    testInfo.esl = ESL1;
    testInfo.publicKey = {1, 2, 3, 4};

    uint64_t testExecutorIndex = 73265;

    testCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockCoAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, ExecutorRegister(_, _, _)).Times(1);
    ON_CALL(*service, ExecutorRegister)
        .WillByDefault(
            [&testInfo, &testExecutorIndex](const IpcExecutorRegisterInfo &info,
                const sptr<IExecutorCallback> &callback, uint64_t &executorIndex) {
                EXPECT_EQ(testInfo.authType, info.authType);
                EXPECT_EQ(testInfo.executorRole, info.executorRole);
                EXPECT_EQ(testInfo.executorSensorHint, info.executorSensorHint);
                EXPECT_EQ(testInfo.executorMatcher, info.executorMatcher);
                EXPECT_EQ(testInfo.esl, info.esl);
                EXPECT_THAT(testInfo.publicKey, ElementsAreArray(info.publicKey));
                executorIndex = testExecutorIndex;
                return SUCCESS;
            }
        );
    
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr, 73265);


    CoAuthClient::GetInstance().Register(testInfo, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

void CoAuthClientTest::CallRemoteObject(const std::shared_ptr<MockCoAuthService> service,
    const sptr<MockRemoteObject> &obj, sptr<IRemoteObject::DeathRecipient> &dr, uint64_t testExecutorIndex)
{
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillRepeatedly([&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
            dr = recipient;
            return true;
        });

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([service, testExecutorIndex](uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            uint64_t executorIndex = 0;
            int32_t ret = 0;
            EXPECT_TRUE(reply.ReadInt32(ret));
            EXPECT_TRUE(reply.ReadUint64(executorIndex));
            EXPECT_EQ(executorIndex, testExecutorIndex);
            return OHOS::NO_ERROR;
        });
}

HWTEST_F(CoAuthClientTest, CoAuthClientRegister_002, TestSize.Level0)
{
    ExecutorInfo testInfo = {};
    IpcClientUtils::ResetObj();
    auto testCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    EXPECT_NE(testCallback, nullptr);

    CoAuthClient::GetInstance().Register(testInfo, testCallback);
}

HWTEST_F(CoAuthClientTest, CoAuthClientRegister_004, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));

    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillOnce(Return(false))
        .WillRepeatedly([&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
            dr = recipient;
            return true;
        });

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).WillRepeatedly(Return(OHOS::NO_ERROR));

    IpcClientUtils::SetObj(obj);

    ExecutorInfo testInfo = {};
    auto testCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    EXPECT_NE(testCallback, nullptr);
    CoAuthClient::GetInstance().Register(testInfo, testCallback);
    CoAuthClient::GetInstance().Register(testInfo, testCallback);
    CoAuthClient::GetInstance().Register(testInfo, testCallback);

    EXPECT_NE(dr, nullptr);
    sptr<IRemoteObject> remote(nullptr);
    dr->OnRemoteDied(remote);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(CoAuthClientTest, CoAuthClientUnregister001, TestSize.Level0)
{
    uint64_t executorIndex = 73265;
    IpcClientUtils::ResetObj();
    EXPECT_NO_THROW(CoAuthClient::GetInstance().Unregister(executorIndex));
}

HWTEST_F(CoAuthClientTest, CoAuthClientUnregister002, TestSize.Level0)
{
    uint64_t executorIndex = 73265;
    auto service = Common::MakeShared<MockCoAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, ExecutorUnregister(_)).Times(1);
    ON_CALL(*service, ExecutorUnregister).WillByDefault(Return(SUCCESS));

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillRepeatedly([&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
            dr = recipient;
            return true;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });

    EXPECT_NO_THROW(CoAuthClient::GetInstance().Unregister(executorIndex));
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
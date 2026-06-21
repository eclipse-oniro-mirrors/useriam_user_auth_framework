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

#include "remote_auth_callback_manager.h"

#include <gtest/gtest.h>

#include "mock_remote_auth_callback.h"
#include "iam_ptr.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class MockIRemoteAuthCallback : public IRemoteStub<IRemoteAuthCallback> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD3(OnRemoteAuthResult,
        int32_t(int32_t result, const std::vector<uint8_t> &extraInfo, const std::vector<uint8_t> &licenseInfo));
    MOCK_METHOD2(OnGetRemoteAuthWidgetParam,
        int32_t(const std::vector<uint8_t> &challenge, const sptr<ISetWidgetParamCallback> &callback));
    sptr<IRemoteObject> AsObject() override
    {
        return sptr<IRemoteObject>(new (std::nothrow) MockIRemoteObject());
    }
};

class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject(u16"mock") {}
    int GetObjectRefCount() override
    {
        return 1;
    }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }
    bool IsProxyObject() const override
    {
        return true;
    }
    bool CheckObjectLegality() const override
    {
        return true;
    }
    int AddDeathRecipient(sptr<IRemoteObject::DeathRecipient> recipient) override
    {
        return 0;
    }
    int RemoveDeathRecipient(sptr<IRemoteObject::DeathRecipient> recipient) override
    {
        return 0;
    }
    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }
};
}

class RemoteAuthCallbackManagerTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void RemoteAuthCallbackManagerTest::SetUpTestCase()
{
}

void RemoteAuthCallbackManagerTest::TearDownTestCase()
{
}

void RemoteAuthCallbackManagerTest::SetUp()
{
}

void RemoteAuthCallbackManagerTest::TearDown()
{
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerAddCallback_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t tokenId = 12345;
    std::string callerName = "test";
    EXPECT_EQ(manager->AddRemoteAuthCallback(tokenId, callback, callerName), SUCCESS);
    manager->DelRemoteAuthCallback(tokenId);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerAddCallback_002, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = nullptr;
    uint32_t tokenId = 12345;
    std::string callerName = "test";
    EXPECT_EQ(manager->AddRemoteAuthCallback(tokenId, callback, callerName), GENERAL_ERROR);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerDelCallback_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t tokenId = 12345;
    std::string callerName = "test";
    manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    EXPECT_EQ(manager->DelRemoteAuthCallback(tokenId), SUCCESS);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerDelCallback_002, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    uint32_t tokenId = 99999;
    EXPECT_EQ(manager->DelRemoteAuthCallback(tokenId), SUCCESS);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerGetCallback_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t tokenId = 12345;
    std::string callerName = "test";
    manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    auto result = manager->GetRemoteAuthCallback(tokenId);
    EXPECT_NE(result, nullptr);
    manager->DelRemoteAuthCallback(tokenId);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerGetCallback_002, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    uint32_t tokenId = 99999;
    auto result = manager->GetRemoteAuthCallback(tokenId);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerAddDuplicateCallback_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t tokenId = 12345;
    std::string callerName = "test";
    EXPECT_EQ(manager->AddRemoteAuthCallback(tokenId, callback, callerName), SUCCESS);
    EXPECT_EQ(manager->AddRemoteAuthCallback(tokenId, callback, callerName), SUCCESS);
    manager->DelRemoteAuthCallback(tokenId);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerAddMultipleCallbacks_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback1 = new (std::nothrow) MockIRemoteAuthCallback();
    sptr<MockIRemoteAuthCallback> callback2 = new (std::nothrow) MockIRemoteAuthCallback();
    sptr<MockIRemoteAuthCallback> callback3 = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);
    ASSERT_NE(callback3, nullptr);

    uint32_t tokenId1 = 11111;
    uint32_t tokenId2 = 22222;
    uint32_t tokenId3 = 33333;
    std::string callerName = "test";

    EXPECT_EQ(manager->AddRemoteAuthCallback(tokenId1, callback1, callerName), SUCCESS);
    EXPECT_EQ(manager->AddRemoteAuthCallback(tokenId2, callback2, callerName), SUCCESS);
    EXPECT_EQ(manager->AddRemoteAuthCallback(tokenId3, callback3, callerName), SUCCESS);

    EXPECT_NE(manager->GetRemoteAuthCallback(tokenId1), nullptr);
    EXPECT_NE(manager->GetRemoteAuthCallback(tokenId2), nullptr);
    EXPECT_NE(manager->GetRemoteAuthCallback(tokenId3), nullptr);

    manager->DelRemoteAuthCallback(tokenId1);
    manager->DelRemoteAuthCallback(tokenId2);
    manager->DelRemoteAuthCallback(tokenId3);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerDelAndGetCallback_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t tokenId = 12345;
    std::string callerName = "test";
    manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    manager->DelRemoteAuthCallback(tokenId);
    auto result = manager->GetRemoteAuthCallback(tokenId);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerGetCallbackDeathRecipientMap_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t tokenId = 12345;
    std::string callerName = "test";
    manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    auto map = manager->GetCallbackDeathRecipientMap();
    EXPECT_GE(map.size(), 0);
    manager->DelRemoteAuthCallback(tokenId);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerOnRemoteDied_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t tokenId = 12345;
    std::string callerName = "test";
    manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    auto map = manager->GetCallbackDeathRecipientMap();
    manager->DelRemoteAuthCallback(tokenId);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerDelRemoteAuthCallbackOnRemoteDied_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t tokenId = 12345;
    std::string callerName = "test";
    manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    EXPECT_EQ(manager->DelRemoteAuthCallbackOnRemoteDied(callback), SUCCESS);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerDelRemoteAuthCallbackOnRemoteDied_002, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = nullptr;
    EXPECT_EQ(manager->DelRemoteAuthCallbackOnRemoteDied(callback), GENERAL_ERROR);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerGetCallerName_001, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    sptr<MockIRemoteAuthCallback> callback = new (std::nothrow) MockIRemoteAuthCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t tokenId = 12345;
    std::string callerName = "test_caller";
    manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    EXPECT_EQ(manager->GetRemoteAuthCallerName(tokenId), callerName);
    manager->DelRemoteAuthCallback(tokenId);
}

HWTEST_F(RemoteAuthCallbackManagerTest, RemoteAuthCallbackManagerGetCallerName_002, TestSize.Level0)
{
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    uint32_t tokenId = 99999;
    EXPECT_EQ(manager->GetRemoteAuthCallerName(tokenId), "");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
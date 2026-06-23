/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "event_listener_manager_test.h"
#include "event_listener_manager.h"

#include "gtest/gtest.h"
#include "mock_event_listener.h"
#include "mock_remote_object.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void EventListenerManagerTest::SetUpTestCase()
{
}

void EventListenerManagerTest::TearDownTestCase()
{
}

void EventListenerManagerTest::SetUp()
{
}

void EventListenerManagerTest::TearDown()
{
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRegistEventListener, TestSize.Level0)
{
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_EQ(AuthEventListenerManager::GetInstance().RegistEventListener(nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RegistEventListener(testCallback));

    EXPECT_EQ(CredChangeEventListenerManager::GetInstance().RegistEventListener(nullptr),
        GENERAL_ERROR);
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().RegistEventListener(testCallback));
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestUnRegistEventListener, TestSize.Level0)
{
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_EQ(AuthEventListenerManager::GetInstance().UnRegistEventListener(nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().UnRegistEventListener(testCallback));

    EXPECT_EQ(CredChangeEventListenerManager::GetInstance().UnRegistEventListener(nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().UnRegistEventListener(testCallback));
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRemoveDeathRecipient_001, TestSize.Level0)
{
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RemoveDeathRecipient(testCallback));
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RemoveDeathRecipient(nullptr));
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().RemoveDeathRecipient(testCallback));
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().RemoveDeathRecipient(nullptr));
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRemoveDeathRecipient_002, TestSize.Level0)
{
    sptr<MockEventListener> mockCallbackRemove = new MockEventListener();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*mockCallbackRemove, AsObject())
        .WillRepeatedly(Return(obj));
    
    AuthEventListenerManager &authEventListenerManager = AuthEventListenerManager::GetInstance();
    EXPECT_EQ(authEventListenerManager.RemoveDeathRecipient(mockCallbackRemove), SUCCESS);
}

// IsProxyObject() returns true, AddDeathRecipient fails
HWTEST_F(EventListenerManagerTest, EventListenerManagerTestAddDeathRecipient_001, TestSize.Level0)
{
    sptr<MockEventListener> mockCallbackAdd = new MockEventListener();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*mockCallbackAdd, AsObject())
        .WillRepeatedly(Return(obj));

    EXPECT_CALL(*obj, IsProxyObject())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillOnce(Return(false));

    AuthEventListenerManager &authEventListenerManager = AuthEventListenerManager::GetInstance();
    EXPECT_EQ(authEventListenerManager.AddDeathRecipient(&authEventListenerManager, mockCallbackAdd), GENERAL_ERROR);
}

// IsProxyObject() returns true, AddDeathRecipient succeeds
HWTEST_F(EventListenerManagerTest, EventListenerManagerTestAddDeathRecipient_002, TestSize.Level0)
{
    sptr<MockEventListener> mockCallbackAdd = new MockEventListener();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*mockCallbackAdd, AsObject())
        .WillRepeatedly(Return(obj));

    EXPECT_CALL(*obj, IsProxyObject())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillRepeatedly(Return(true));

    AuthEventListenerManager &authEventListenerManager = AuthEventListenerManager::GetInstance();
    EXPECT_EQ(authEventListenerManager.AddDeathRecipient(&authEventListenerManager, mockCallbackAdd), SUCCESS);
    EXPECT_EQ(authEventListenerManager.AddDeathRecipient(&authEventListenerManager, mockCallbackAdd), SUCCESS);
}

// IsProxyObject() returns false (same process stub), should NOT call AddDeathRecipient
HWTEST_F(EventListenerManagerTest, EventListenerManagerTestAddDeathRecipient_SameProcess, TestSize.Level0)
{
    sptr<MockEventListener> mockCallbackAdd = new MockEventListener();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*mockCallbackAdd, AsObject())
        .WillRepeatedly(Return(obj));

    // Same process stub: IsProxyObject() returns false
    EXPECT_CALL(*obj, IsProxyObject())
        .WillRepeatedly(Return(false));
    // AddDeathRecipient should NOT be called for same process stub
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .Times(0);

    CredChangeEventListenerManager &manager = CredChangeEventListenerManager::GetInstance();
    EXPECT_EQ(manager.AddDeathRecipient(&manager, mockCallbackAdd), SUCCESS);
}

// Remove listener that was registered with IsProxyObject() = false (same process stub)
HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRemoveDeathRecipient_SameProcess, TestSize.Level0)
{
    sptr<MockEventListener> mockCallback = new MockEventListener();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*mockCallback, AsObject())
        .WillRepeatedly(Return(obj));

    // Same process stub: IsProxyObject() returns false
    EXPECT_CALL(*obj, IsProxyObject())
        .WillRepeatedly(Return(false));
    // AddDeathRecipient should NOT be called for same process stub
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .Times(0);
    // RemoveDeathRecipient should NOT be called when deathRecipient is nullptr
    EXPECT_CALL(*obj, RemoveDeathRecipient(_))
        .Times(0);

    CredChangeEventListenerManager &manager = CredChangeEventListenerManager::GetInstance();
    // Register with same process stub
    EXPECT_EQ(manager.AddDeathRecipient(&manager, mockCallback), SUCCESS);
    // Remove should succeed without calling RemoveDeathRecipient
    EXPECT_EQ(manager.RemoveDeathRecipient(mockCallback), SUCCESS);
}

// Remove listener that was registered with IsProxyObject() = true (proxy object)
HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRemoveDeathRecipient_Proxy, TestSize.Level0)
{
    sptr<MockEventListener> mockCallback = new MockEventListener();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*mockCallback, AsObject())
        .WillRepeatedly(Return(obj));

    // Proxy object: IsProxyObject() returns true
    EXPECT_CALL(*obj, IsProxyObject())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillRepeatedly(Return(true));
    // RemoveDeathRecipient SHOULD be called for proxy object
    EXPECT_CALL(*obj, RemoveDeathRecipient(_))
        .WillOnce(Return(true));

    AuthEventListenerManager &manager = AuthEventListenerManager::GetInstance();
    // Register with proxy object
    EXPECT_EQ(manager.AddDeathRecipient(&manager, mockCallback), SUCCESS);
    // Remove should call RemoveDeathRecipient
    EXPECT_EQ(manager.RemoveDeathRecipient(mockCallback), SUCCESS);
}

HWTEST_F(EventListenerManagerTest, OnRemoteDiedTest, TestSize.Level0)
{
    AuthEventListenerManager &manager = AuthEventListenerManager::GetInstance();
    sptr<EventListenerManager::EventListenerDeathRecipient> dr(
        new (std::nothrow)AuthEventListenerManager::EventListenerDeathRecipient(&manager));
    wptr<IRemoteObject> remote = nullptr;
    EXPECT_NO_THROW(dr->OnRemoteDied(remote));

    auto mro = new MockRemoteObject();
    EXPECT_NO_THROW(dr->OnRemoteDied(mro));
}

HWTEST_F(EventListenerManagerTest, OnNotifyCredChangeEventTest, TestSize.Level0)
{
    EventListenerManager manager = {};
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    CredChangeEventListenerManager::GetInstance().AddDeathRecipient(&manager, testCallback);

    int32_t userId = 0;
    AuthType authType = AuthType::PIN;
    CredChangeEventType eventType = {};
    CredChangeEventInfo changeInfo = {};
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance()
        .OnNotifyCredChangeEvent(userId, authType, eventType, changeInfo));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
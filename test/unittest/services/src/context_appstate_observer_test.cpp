/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "context_appstate_observer_test.h"

#include <gtest/gtest.h>
#include <thread>

#include "accesstoken_kit.h"
#include "app_state_data.h"
#include "context_appstate_observer.h"
#include "mock_context.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "context_pool.h"
#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace std;
using namespace testing;
using namespace testing::ext;
void ContextAppStateObserverTest::SetUpTestCase()
{
}

void ContextAppStateObserverTest::TearDownTestCase()
{
}

void ContextAppStateObserverTest::SetUp()
{
}

void ContextAppStateObserverTest::TearDown()
{
}

HWTEST_F(ContextAppStateObserverTest, SubscribeAppStateTest_001, TestSize.Level0)
{
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    uint64_t contextId = 1;
    EXPECT_CALL(*contextCallback, GetCallerName())
        .WillRepeatedly([]() {
                return "com.homs.settings";
            }
        );
    auto appStateObserverManager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(appStateObserverManager, nullptr);
    appStateObserverManager->SubscribeAppState(contextId, contextCallback);
    appStateObserverManager->UnSubscribeAppState(contextId);
}

HWTEST_F(ContextAppStateObserverTest, SubscribeAppStateTest_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserverManager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(appStateObserverManager, nullptr);
    appStateObserverManager->SubscribeAppState(contextId, nullptr);
}

HWTEST_F(ContextAppStateObserverTest, SubscribeAppStateTest_003, TestSize.Level0)
{
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    uint64_t contextId = 1;
    EXPECT_CALL(*contextCallback, GetCallerName())
        .WillRepeatedly([]() {
                return "";
            }
        );
    auto appStateObserverManager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(appStateObserverManager, nullptr);
    appStateObserverManager->SubscribeAppState(contextId, contextCallback);
}

HWTEST_F(ContextAppStateObserverTest, UnSubscribeAppStateTest_001, TestSize.Level0)
{
    auto appStateObserverManager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(appStateObserverManager, nullptr);
    appStateObserverManager->UnSubscribeAppState(1);
}

HWTEST_F(ContextAppStateObserverTest, UnSubscribeAppStateTest_002, TestSize.Level0)
{
    auto appStateObserverManager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(appStateObserverManager, nullptr);
    uint64_t contextId = 1;
    std::string bundelName = "com.homs.settings";
    appStateObserverManager->appStateObservers_[contextId] =
        new (std::nothrow) ContextAppStateObserver(contextId, bundelName);
    appStateObserverManager->UnSubscribeAppState(contextId);
}

HWTEST_F(ContextAppStateObserverTest, OnAppStateChangedTest_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.settings");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnAppStateChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnAppStateChangedTest_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.settings");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnAppStateChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnAppStateChangedTest_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.setting");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnAppStateChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnForegroundApplicationChangedTest_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.settings");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnForegroundApplicationChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnForegroundApplicationChangedTest_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.settings");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnForegroundApplicationChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnForegroundApplicationChangedTest_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.setting");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnForegroundApplicationChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, ProcAppStateChangedTest_001, TestSize.Level0)
{
    int32_t userId = 100;
    uint64_t contextId = 1;
    uint32_t tokenId = 0x1234;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.setting");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";
    auto context = Common::MakeShared<MockContext>();
    EXPECT_NE(context, nullptr);
    EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(contextId));
    EXPECT_CALL(*context, GetLatestError()).WillRepeatedly(Return(GENERAL_ERROR));
    EXPECT_CALL(*context, GetTokenId()).WillRepeatedly(Return(tokenId));
    EXPECT_CALL(*context, GetUserId())
        .WillOnce(Return(101))
        .WillRepeatedly(Return(userId));
    EXPECT_CALL(*context, Stop())
        .WillRepeatedly(Return(true));
    EXPECT_TRUE(ContextPool::Instance().Schedule(context));
    appStateObserver->ProcAppStateChanged(userId);
    appStateObserver->ProcAppStateChanged(userId);
    appStateObserver->ProcAppStateChanged(userId);
    EXPECT_TRUE(ContextPool::Instance().Delete(contextId));
}

HWTEST_F(ContextAppStateObserverTest, MultiContextSubscriptionNoEviction, TestSize.Level0)
{
    auto manager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(manager, nullptr);
    // two coexisting contexts each own an observer: neither may evict the other
    manager->appStateObservers_[1] = new (std::nothrow) ContextAppStateObserver(1, "com.homs.settings");
    manager->appStateObservers_[2] = new (std::nothrow) ContextAppStateObserver(2, "com.homs.other");
    ASSERT_EQ(manager->appStateObservers_.size(), 2UL);

    // the finished context unregisters ONLY its own entry
    manager->UnSubscribeAppState(1);
    EXPECT_EQ(manager->appStateObservers_.size(), 1UL);
    EXPECT_EQ(manager->appStateObservers_.count(2), 1UL);

    // the surviving observer still cancels its own context on background
    auto survivor = manager->appStateObservers_[2];
    ASSERT_NE(survivor, nullptr);
    auto context = MockContext::CreateWithContextId(2);
    ASSERT_NE(context, nullptr);
    auto contextMock = std::static_pointer_cast<MockContext>(context);
    ON_CALL(*contextMock, GetUserId()).WillByDefault(Return(0));
    EXPECT_CALL(*contextMock, Stop()).Times(1);
    ASSERT_TRUE(ContextPool::Instance().Schedule(context));
    AppStateData appStateData;
    appStateData.bundleName = "com.homs.other";
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.uid = 0;
    survivor->OnAppStateChanged(appStateData);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    handler->EnsureTask([]() {});
    Mock::VerifyAndClearExpectations(contextMock.get());
    EXPECT_TRUE(ContextPool::Instance().Delete(2));
}

HWTEST_F(ContextAppStateObserverTest, SubscribeAppStateTest_004, TestSize.Level0)
{
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    uint64_t contextId1 = 1;
    uint64_t contextId2 = 2;
    EXPECT_CALL(*contextCallback, GetCallerName())
        .WillRepeatedly([]() {
                return "com.homs.settings";
            }
        );
    
    auto manager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(manager, nullptr);
    
    sptr<ApplicationStateObserverStub> oldObserver =
        new (std::nothrow) ContextAppStateObserver(contextId1, "com.homs.settings");
    ASSERT_NE(oldObserver, nullptr);
    manager->appStateObservers_[contextId1] = oldObserver;
    
    manager->SubscribeAppState(contextId2, contextCallback);
    
    manager->UnSubscribeAppState(contextId1);
}

HWTEST_F(ContextAppStateObserverTest, ConcurrentSubscribeTest_001, TestSize.Level0)
{
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    uint64_t contextId1 = 1;
    uint64_t contextId2 = 2;
    EXPECT_CALL(*contextCallback, GetCallerName())
        .WillRepeatedly([]() {
                return "com.homs.settings";
            }
        );
    
    auto manager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(manager, nullptr);
    
    std::thread thread1([manager, contextCallback, contextId1]() {
        manager->SubscribeAppState(contextId1, contextCallback);
    });
    
    std::thread thread2([manager, contextCallback, contextId2]() {
        manager->SubscribeAppState(contextId2, contextCallback);
    });
    
    thread1.join();
    thread2.join();
    
    for (auto &entry : manager->appStateObservers_) {
        manager->UnSubscribeAppState(entry.first);
    }
}

HWTEST_F(ContextAppStateObserverTest, ConcurrentSubscribeUnSubscribeTest_001, TestSize.Level0)
{
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    uint64_t contextId = 1;
    EXPECT_CALL(*contextCallback, GetCallerName())
        .WillRepeatedly([]() {
                return "com.homs.settings";
            }
        );
    
    auto manager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(manager, nullptr);
    
    std::thread thread1([manager, contextCallback, contextId]() {
        manager->SubscribeAppState(contextId, contextCallback);
    });
    
    std::thread thread2([contextId, manager]() {
        manager->UnSubscribeAppState(contextId);
    });
    
    thread1.join();
    thread2.join();
}

HWTEST_F(ContextAppStateObserverTest, ConcurrentUnSubscribeTest_001, TestSize.Level0)
{
    auto manager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(manager, nullptr);
    
    uint64_t contextId = 1;
    std::string bundelName = "com.homs.settings";
    manager->appStateObservers_[contextId] =
        new (std::nothrow) ContextAppStateObserver(contextId, bundelName);
    
    std::thread thread1([contextId, manager]() {
        manager->UnSubscribeAppState(contextId);
    });
    
    std::thread thread2([contextId, manager]() {
        manager->UnSubscribeAppState(contextId);
    });
    
    thread1.join();
    thread2.join();
}

HWTEST_F(ContextAppStateObserverTest, MutexProtectionTest_001, TestSize.Level0)
{
    auto manager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(manager, nullptr);
    
    uint64_t contextId = 1;
    std::string bundelName = "com.homs.settings";
    manager->appStateObservers_[contextId] =
        new (std::nothrow) ContextAppStateObserver(contextId, bundelName);
    
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, GetCallerName())
        .WillRepeatedly([]() {
                return "com.homs.settings";
            }
        );
    
    std::thread thread1([manager, contextCallback, contextId]() {
        manager->SubscribeAppState(contextId, contextCallback);
    });
    
    std::thread thread2([contextId, manager]() {
        manager->UnSubscribeAppState(contextId);
    });
    
    std::thread thread3([manager, contextCallback, contextId]() {
        manager->SubscribeAppState(contextId, contextCallback);
    });
    
    thread1.join();
    thread2.join();
    thread3.join();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
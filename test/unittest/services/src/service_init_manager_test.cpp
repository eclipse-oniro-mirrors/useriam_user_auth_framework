/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "service_init_manager_test.h"
#include "service_init_manager.h"

#include "device_manager_util.h"
#include "mock_user_auth_engine.h"
#include "system_ability_listener.h"
#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

using namespace testing;
using namespace testing::ext;

namespace {
void DrainSingleThread()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    handler->EnsureTask([]() {});
}

void ResetManager(ServiceInitManager &manager)
{
    manager.OnIdmServiceStop();
    manager.OnCoAuthServiceStop();
    manager.OnUserAuthServiceStop();
    DrainSingleThread();
}
} // namespace

void ServiceInitManagerTest::SetUpTestCase()
{
}

void ServiceInitManagerTest::TearDownTestCase()
{
}

void ServiceInitManagerTest::SetUp()
{
    MockUserAuthEngine::Holder::GetInstance().Reset();
    auto &manager = ServiceInitManager::GetInstance();
    ResetManager(manager);
}

void ServiceInitManagerTest::TearDown()
{
    MockUserAuthEngine::Holder::GetInstance().Reset();
    auto &manager = ServiceInitManager::GetInstance();
    ResetManager(manager);
}

// 基本启停不抛异常
HWTEST_F(ServiceInitManagerTest, ServiceInitManagerOnStartStopNoThrow, TestSize.Level0)
{
    EXPECT_NO_THROW({
        ServiceInitManager::GetInstance().OnIdmServiceStart();
        ServiceInitManager::GetInstance().OnIdmServiceStop();
        ServiceInitManager::GetInstance().OnCoAuthServiceStart();
        ServiceInitManager::GetInstance().OnCoAuthServiceStop();
        ServiceInitManager::GetInstance().OnUserAuthServiceStart();
        ServiceInitManager::GetInstance().OnUserAuthServiceStop();
        DrainSingleThread();
    });
}

// 单 SA 启动后对应标记置位
HWTEST_F(ServiceInitManagerTest, SingleStartSetsFlag, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    DrainSingleThread();
    EXPECT_TRUE(manager.isCoAuthServiceStart_);
    EXPECT_FALSE(manager.isUserAuthServiceStart_);
    EXPECT_FALSE(manager.isIdmServiceStart_);
}

// 单/双 SA 启动不触发全局初始化（fwkReady_ 仍为 false）
HWTEST_F(ServiceInitManagerTest, SingleStartDoesNotTriggerGlobalInit, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    DrainSingleThread();
    EXPECT_FALSE(manager.fwkReady_);

    manager.OnUserAuthServiceStart();
    DrainSingleThread();
    EXPECT_FALSE(manager.fwkReady_);
}

// 3 个 SA 全启动才触发全局初始化（fwkReady_ 置位）
HWTEST_F(ServiceInitManagerTest, ThirdStartTriggersGlobalInit, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();
    DrainSingleThread();
    EXPECT_FALSE(manager.fwkReady_);

    manager.OnIdmServiceStart();
    DrainSingleThread();
    EXPECT_TRUE(manager.fwkReady_);
}

// 已初始化后再次启动不重复触发（fwkReady_ 保持 true）
HWTEST_F(ServiceInitManagerTest, AlreadyInitedDoesNotRetrigger, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();
    manager.OnIdmServiceStart();
    DrainSingleThread();
    EXPECT_TRUE(manager.fwkReady_);

    manager.OnCoAuthServiceStop();
    DrainSingleThread();
    manager.OnCoAuthServiceStart();
    DrainSingleThread();
    EXPECT_TRUE(manager.fwkReady_);
}

// OnAccessTokenReady 置 accessTokenReady_
HWTEST_F(ServiceInitManagerTest, OnAccessTokenReadySetsFlag, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    EXPECT_FALSE(manager.accessTokenReady_);
    manager.OnAccessTokenReady();
    DrainSingleThread();
    EXPECT_TRUE(manager.accessTokenReady_);
}

// OnEngineUnavailable 清零 engineReady_
HWTEST_F(ServiceInitManagerTest, OnEngineUnavailableClearsFlag, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.engineReady_ = true;
    manager.OnEngineUnavailable();
    DrainSingleThread();
    EXPECT_FALSE(manager.engineReady_);
}

// 缺 engineReady_ 时即便其余 5 标记全 true 也不触发 Publish/OnFwkReady（无异常）
HWTEST_F(ServiceInitManagerTest, MissingEngineReadyNoPublish, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.isCoAuthServiceStart_ = true;
    manager.isUserAuthServiceStart_ = true;
    manager.isIdmServiceStart_ = true;
    manager.accessTokenReady_ = true;
    manager.fwkReady_ = true;
    manager.engineReady_ = false;
    EXPECT_NO_THROW(manager.CheckAllFlags());
    DrainSingleThread();
}

// 6 标记全 true 时 CheckAllFlags 不抛异常（PublishAllServices 内 samgr 不可用，预期不抛）
HWTEST_F(ServiceInitManagerTest, AllFlagsReadyCheckAllFlagsNoThrow, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.isCoAuthServiceStart_ = true;
    manager.isUserAuthServiceStart_ = true;
    manager.isIdmServiceStart_ = true;
    manager.accessTokenReady_ = true;
    manager.fwkReady_ = true;
    manager.engineReady_ = true;
    EXPECT_NO_THROW(manager.CheckAllFlags());
    DrainSingleThread();
}

// 3 SA 全停触发 DeinitGlobalInstance，复位标记
HWTEST_F(ServiceInitManagerTest, AllStopDeinitGlobalInstance, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();
    manager.OnIdmServiceStart();
    DrainSingleThread();
    EXPECT_TRUE(manager.fwkReady_);

    manager.OnCoAuthServiceStop();
    manager.OnUserAuthServiceStop();
    DrainSingleThread();
    // 仅 2 个停止，不应反初始化
    EXPECT_TRUE(manager.fwkReady_);

    manager.OnIdmServiceStop();
    DrainSingleThread();
    // 3 个全停，应反初始化
    EXPECT_FALSE(manager.fwkReady_);
    EXPECT_FALSE(manager.accessTokenReady_);
    EXPECT_FALSE(manager.engineReady_);
    EXPECT_FALSE(manager.isCoAuthServiceStart_);
    EXPECT_FALSE(manager.isUserAuthServiceStart_);
    EXPECT_FALSE(manager.isIdmServiceStart_);
}

// 重启后可再次触发全局初始化
HWTEST_F(ServiceInitManagerTest, RestartRetriggersGlobalInit, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();
    manager.OnIdmServiceStart();
    DrainSingleThread();
    EXPECT_TRUE(manager.fwkReady_);

    manager.OnCoAuthServiceStop();
    manager.OnUserAuthServiceStop();
    manager.OnIdmServiceStop();
    DrainSingleThread();
    EXPECT_FALSE(manager.fwkReady_);

    // 重启需 3 个 SA 全启动才重新触发
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();
    DrainSingleThread();
    EXPECT_FALSE(manager.fwkReady_);

    manager.OnIdmServiceStart();
    DrainSingleThread();
    EXPECT_TRUE(manager.fwkReady_);
}

// 单 SA 停止不影响其他标记
HWTEST_F(ServiceInitManagerTest, SingleStopKeepsOthers, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.OnCoAuthServiceStart();
    manager.OnUserAuthServiceStart();
    manager.OnIdmServiceStart();
    DrainSingleThread();

    manager.OnCoAuthServiceStop();
    DrainSingleThread();
    EXPECT_FALSE(manager.isCoAuthServiceStart_);
    EXPECT_TRUE(manager.isUserAuthServiceStart_);
    EXPECT_TRUE(manager.isIdmServiceStart_);
    EXPECT_TRUE(manager.fwkReady_);
}

// OnEngineReady 全流程成功：engineReady_ 置位
HWTEST_F(ServiceInitManagerTest, OnEngineReadyFullSuccess, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    DeviceManagerUtil::GetInstance().localUdid_ = std::optional<std::string>("testUdid");
    EXPECT_CALL(*mockHdi, Init(_)).Times(1).WillOnce(Return(SUCCESS));
    EXPECT_CALL(*mockHdi, RegisterMessageCallback(_)).Times(1).WillOnce(Return(SUCCESS));
    manager.engineReady_ = false;
    manager.OnEngineReady();
    DrainSingleThread();
    EXPECT_TRUE(manager.engineReady_);
}

// OnEngineReady 幂等：已就绪直接返回，不再调 Init
HWTEST_F(ServiceInitManagerTest, OnEngineReadyAlreadyReady, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    manager.engineReady_ = true;
    EXPECT_CALL(*mockHdi, Init(_)).Times(0);
    EXPECT_CALL(*mockHdi, RegisterMessageCallback(_)).Times(0);
    manager.OnEngineReady();
    DrainSingleThread();
    EXPECT_TRUE(manager.engineReady_);
}

// OnEngineReady Init 失败：engineReady_ 保持 false
HWTEST_F(ServiceInitManagerTest, OnEngineReadyInitFail, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    DeviceManagerUtil::GetInstance().localUdid_ = std::optional<std::string>("testUdid");
    EXPECT_CALL(*mockHdi, Init(_)).Times(1).WillOnce(Return(GENERAL_ERROR));
    manager.engineReady_ = false;
    manager.OnEngineReady();
    DrainSingleThread();
    EXPECT_FALSE(manager.engineReady_);
}

// OnEngineUnavailable 未就绪：跳过清理分支
HWTEST_F(ServiceInitManagerTest, OnEngineUnavailableNotReady, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.engineReady_ = false;
    EXPECT_NO_THROW(manager.OnEngineUnavailable());
    DrainSingleThread();
    EXPECT_FALSE(manager.engineReady_);
}

// RegisterAccessTokenListener 幂等：已有 listener 直接 SUCCESS
HWTEST_F(ServiceInitManagerTest, RegisterAccessTokenListenerIdempotent, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.accessTokenListener_ = sptr<SystemAbilityListener>(
        new (std::nothrow) SystemAbilityListener("test", 1, nullptr, nullptr));
    EXPECT_NE(manager.accessTokenListener_, nullptr);
    EXPECT_EQ(manager.RegisterAccessTokenListenerImpl(), SUCCESS);
    manager.accessTokenListener_ = nullptr;
}

// RegisterAccessTokenListener 订阅路径（成败由环境决定，均不抛异常）
HWTEST_F(ServiceInitManagerTest, RegisterAccessTokenListenerSubscribePath, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.accessTokenListener_ = nullptr;
    EXPECT_NO_THROW(manager.RegisterAccessTokenListenerImpl());
}

// UnRegisterAccessTokenListener 有 listener：走 UnSubscribe 路径
HWTEST_F(ServiceInitManagerTest, UnRegisterAccessTokenListenerWithListener, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    manager.accessTokenListener_ = sptr<SystemAbilityListener>(
        new (std::nothrow) SystemAbilityListener("test", 1, nullptr, nullptr));
    EXPECT_NE(manager.accessTokenListener_, nullptr);
    EXPECT_NO_THROW(manager.UnRegisterAccessTokenListenerImpl());
    manager.accessTokenListener_ = nullptr;
}

// threadHandler_ 为空时 9 个公开方法早返回
HWTEST_F(ServiceInitManagerTest, ThreadHandlerNullEarlyReturn, TestSize.Level0)
{
    auto &manager = ServiceInitManager::GetInstance();
    auto savedHandler = manager.threadHandler_;
    manager.threadHandler_ = nullptr;
    EXPECT_NO_THROW({
        manager.OnCoAuthServiceStart();
        manager.OnCoAuthServiceStop();
        manager.OnUserAuthServiceStart();
        manager.OnUserAuthServiceStop();
        manager.OnIdmServiceStart();
        manager.OnIdmServiceStop();
        manager.OnEngineReady();
        manager.OnEngineUnavailable();
        manager.OnAccessTokenReady();
    });
    manager.threadHandler_ = savedHandler;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

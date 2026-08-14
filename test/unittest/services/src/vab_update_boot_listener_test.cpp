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

#include "vab_update_boot_listener_test.h"

#include "vab_update_boot_listener.h"

#include "iam_logger.h"
#include "relative_timer.h"
#include "system_param_manager.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_VAB_UPDATE_BOOT_LISTENER

namespace OHOS {
namespace UserIam {
namespace UserAuth {

using namespace testing;
using namespace testing::ext;

void VabUpdateBootManagerTest::SetUpTestCase()
{
}

void VabUpdateBootManagerTest::TearDownTestCase()
{
}

void VabUpdateBootManagerTest::SetUp()
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, "");
}

void VabUpdateBootManagerTest::TearDown()
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, "");
}

// Start() returns nullptr when vab_update_boot is not "booting"
HWTEST_F(VabUpdateBootManagerTest, StartNotBooting, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "idle");
    auto listener = VabUpdateBootListener::Start([]() {});
    EXPECT_EQ(listener, nullptr);
}

// Start() returns nullptr when vab_update_boot is empty
HWTEST_F(VabUpdateBootManagerTest, StartEmpty, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "");
    auto listener = VabUpdateBootListener::Start([]() {});
    EXPECT_EQ(listener, nullptr);
}

// Start() creates listener when vab_update_boot is "booting"
HWTEST_F(VabUpdateBootManagerTest, StartBooting, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    bool callbackInvoked = false;
    auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
    EXPECT_NE(listener, nullptr);
    EXPECT_FALSE(callbackInvoked);
}

// OnVabUpdateBoot returns early when boot not completed
HWTEST_F(VabUpdateBootManagerTest, OnVabUpdateBootNotComplete, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, FALSE_STR);

    bool callbackInvoked = false;
    auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
    ASSERT_NE(listener, nullptr);

    listener->OnVabUpdateBoot();
    EXPECT_FALSE(callbackInvoked);
}

// OnVabUpdateBoot returns early when boot completed but vab still "booting"
HWTEST_F(VabUpdateBootManagerTest, OnVabUpdateBootStillBooting, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, TRUE_STR);

    bool callbackInvoked = false;
    auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
    ASSERT_NE(listener, nullptr);

    listener->OnVabUpdateBoot();
    EXPECT_FALSE(callbackInvoked);
}

// OnVabUpdateBoot invokes callback when boot completed and vab no longer "booting"
HWTEST_F(VabUpdateBootManagerTest, OnVabUpdateBootCompleteAndIdle, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, TRUE_STR);

    bool callbackInvoked = false;
    auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
    ASSERT_NE(listener, nullptr);

    // Simulate vab update completes
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "idle");
    listener->OnVabUpdateBoot();
    EXPECT_TRUE(callbackInvoked);
}

// OnVabUpdateBoot sets isBootComplete_ when boot completes
HWTEST_F(VabUpdateBootManagerTest, OnVabUpdateBootBootCompleteTransition, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, FALSE_STR);

    bool callbackInvoked = false;
    auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
    ASSERT_NE(listener, nullptr);

    // Boot not yet complete
    listener->OnVabUpdateBoot();
    EXPECT_FALSE(callbackInvoked);

    // Boot becomes complete, but vab still booting
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, TRUE_STR);
    listener->OnVabUpdateBoot();
    EXPECT_FALSE(callbackInvoked);

    // Vab also completes
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "idle");
    listener->OnVabUpdateBoot();
    EXPECT_TRUE(callbackInvoked);
}

// Timer count reaches limit triggers HandleBootEvent
HWTEST_F(VabUpdateBootManagerTest, OnVabUpdateBootTimerCountReachLimit, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, TRUE_STR);

    bool callbackInvoked = false;
    auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
    ASSERT_NE(listener, nullptr);

    // Exhaust timer count to just above limit
    listener->vabUpdateBootTimerCount_ = 41;
    // Still "booting" but count exceeded -> HandleBootEvent called
    listener->OnVabUpdateBoot();
    EXPECT_TRUE(callbackInvoked);
}

// Timer count below limit increments
HWTEST_F(VabUpdateBootManagerTest, OnVabUpdateBootTimerCountBelowLimit, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, TRUE_STR);

    bool callbackInvoked = false;
    auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
    ASSERT_NE(listener, nullptr);

    listener->vabUpdateBootTimerCount_ = 39;
    listener->OnVabUpdateBoot();
    // vab still "booting", count incremented but no callback
    EXPECT_FALSE(callbackInvoked);
    EXPECT_EQ(listener->vabUpdateBootTimerCount_, 40);
}

// OnVabUpdateBoot returns early when callback_ is null (already handled)
HWTEST_F(VabUpdateBootManagerTest, OnVabUpdateBootCallbackNull, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, TRUE_STR);

    auto listener = VabUpdateBootListener::Start([]() {});
    ASSERT_NE(listener, nullptr);

    // Manually clear callback to simulate already-handled state
    listener->callback_ = nullptr;
    EXPECT_NO_THROW(listener->OnVabUpdateBoot());
}

// Destructor unregisters timer
HWTEST_F(VabUpdateBootManagerTest, DestructorUnregistersTimer, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, FALSE_STR);

    bool callbackInvoked = false;
    {
        auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
        ASSERT_NE(listener, nullptr);
        EXPECT_TRUE(listener->vabUpdateBootTimerId_.has_value());
    }
    // Listener destroyed, timer should be unregistered
    EXPECT_FALSE(callbackInvoked);
}

// HandleBootEvent clears timer and invokes callback
HWTEST_F(VabUpdateBootManagerTest, HandleBootEvent, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");

    bool callbackInvoked = false;
    auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
    ASSERT_NE(listener, nullptr);
    EXPECT_TRUE(listener->vabUpdateBootTimerId_.has_value());

    listener->HandleBootEvent();
    EXPECT_TRUE(callbackInvoked);
    EXPECT_FALSE(listener->vabUpdateBootTimerId_.has_value());
    EXPECT_EQ(listener->callback_, nullptr);
}

// Full integration: boot -> vab booting -> boot complete -> vab idle -> callback
HWTEST_F(VabUpdateBootManagerTest, FullIntegrationFlow, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "booting");
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, FALSE_STR);

    bool callbackInvoked = false;
    auto listener = VabUpdateBootListener::Start([&callbackInvoked]() { callbackInvoked = true; });
    ASSERT_NE(listener, nullptr);

    // First tick: boot not complete
    listener->OnVabUpdateBoot();
    EXPECT_FALSE(callbackInvoked);

    // Second tick: boot complete but vab still booting
    SystemParamManager::GetInstance().SetParam(BOOT_COMPLETE_KEY, TRUE_STR);
    listener->OnVabUpdateBoot();
    EXPECT_FALSE(callbackInvoked);

    // Third tick: vab completes
    SystemParamManager::GetInstance().SetParam(VAB_UPDATE_BOOT_KEY, "idle");
    listener->OnVabUpdateBoot();
    EXPECT_TRUE(callbackInvoked);
    EXPECT_FALSE(listener->vabUpdateBootTimerId_.has_value());
    EXPECT_EQ(listener->callback_, nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

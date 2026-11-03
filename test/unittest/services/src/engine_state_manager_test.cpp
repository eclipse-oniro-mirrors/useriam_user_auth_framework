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

#include "engine_state_manager_test.h"

#include <memory>

#include "engine_state_manager.h"

#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void EngineStateManagerTest::SetUpTestCase()
{
}

void EngineStateManagerTest::TearDownTestCase()
{
}

void EngineStateManagerTest::SetUp()
{
}

void EngineStateManagerTest::TearDown()
{
}

HWTEST_F(EngineStateManagerTest, StartSubscribeTest, TestSize.Level0)
{
    EXPECT_NO_THROW(EngineStateManager::GetInstance().StartSubscribe());
    EXPECT_NO_THROW(EngineStateManager::GetInstance().StartSubscribe());
}

HWTEST_F(EngineStateManagerTest, OnEngineReadyTest, TestSize.Level0)
{
    EXPECT_NO_THROW(EngineStateManager::GetInstance().OnEngineReady());
    EXPECT_NO_THROW(EngineStateManager::GetInstance().OnEngineReady());
}

HWTEST_F(EngineStateManagerTest, OnEngineUnavailableTest, TestSize.Level0)
{
    EXPECT_NO_THROW(EngineStateManager::GetInstance().OnEngineUnavailable());
    EXPECT_NO_THROW(EngineStateManager::GetInstance().OnEngineUnavailable());
    EXPECT_NO_THROW(EngineStateManager::GetInstance().OnEngineReady());
    EXPECT_NO_THROW(EngineStateManager::GetInstance().OnEngineReady());
}

HWTEST_F(EngineStateManagerTest, RegisterEngineReadyCallbackTest, TestSize.Level0)
{
    EXPECT_NO_THROW(EngineStateManager::GetInstance().RegisterEngineReadyCallback(nullptr));
    EXPECT_NO_THROW(EngineStateManager::GetInstance().RegisterEngineReadyCallback([]() { return; }));
}

HWTEST_F(EngineStateManagerTest, RegisterEngineUnavailableCallbackTest, TestSize.Level0)
{
    EXPECT_NO_THROW(EngineStateManager::GetInstance().RegisterEngineUnavailableCallback(nullptr));
    EXPECT_NO_THROW(EngineStateManager::GetInstance().RegisterEngineUnavailableCallback([]() { return; }));
}

// A registered start callback must fire exactly when the engine reports start.
// shared_ptr<bool> by value keeps the flag alive for the singleton's callback lifetime.
HWTEST_F(EngineStateManagerTest, StartCallbackFiresOnEngineReady, TestSize.Level0)
{
    // the real driver-status callback can flip the state to running mid-sequence and
    // spoil the attempt (*fired true at registration); the state is running, so retry
    bool clean = false;
    constexpr int32_t MAX_CLEANUP_RETRIES = 3;
    for (int attempt = 0; attempt < MAX_CLEANUP_RETRIES && !clean; ++attempt) {
        EngineStateManager::GetInstance().OnEngineUnavailable(); // deterministic: not running
        auto fired = std::make_shared<bool>(false);
        EngineStateManager::GetInstance().RegisterEngineReadyCallback([fired]() { *fired = true; });
        if (*fired) {
            continue;
        }
        EngineStateManager::GetInstance().OnEngineReady();
        EXPECT_TRUE(*fired);
        clean = true;
    }
    EXPECT_TRUE(clean);
}

HWTEST_F(EngineStateManagerTest, StartCallbackFiresImmediatelyIfRunning, TestSize.Level0)
{
    EngineStateManager::GetInstance().OnEngineReady(); // deterministic: running
    auto fired = std::make_shared<bool>(false);
    EngineStateManager::GetInstance().RegisterEngineReadyCallback([fired]() { *fired = true; });
    EXPECT_TRUE(*fired);
    EngineStateManager::GetInstance().OnEngineUnavailable(); // reset for other tests
}

HWTEST_F(EngineStateManagerTest, StopCallbackFiresOnEngineUnavailable, TestSize.Level0)
{
    EngineStateManager::GetInstance().OnEngineReady(); // deterministic: running
    auto fired = std::make_shared<bool>(false);
    EngineStateManager::GetInstance().RegisterEngineUnavailableCallback([fired]() { *fired = true; });
    EXPECT_FALSE(*fired);
    EngineStateManager::GetInstance().OnEngineUnavailable();
    EXPECT_TRUE(*fired);
}

// Second OnEngineReady while already running must not re-fire start callbacks.
HWTEST_F(EngineStateManagerTest, StartIsIdempotent, TestSize.Level0)
{
    EngineStateManager::GetInstance().OnEngineReady();
    auto fired = std::make_shared<int>(0);
    EngineStateManager::GetInstance().RegisterEngineReadyCallback([fired]() { *fired += 1; });
    EXPECT_EQ(*fired, 1); // immediate fire (already running)
    EngineStateManager::GetInstance().OnEngineReady(); // no transition -> no extra fire
    EXPECT_EQ(*fired, 1);
    EngineStateManager::GetInstance().OnEngineUnavailable(); // reset
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

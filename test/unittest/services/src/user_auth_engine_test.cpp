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

#include <memory>

#include <gtest/gtest.h>

#include "mock_iuser_auth_interface.h"
#include "user_auth_engine.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class UserAuthEngineTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

// The engine singleton (HDI variant in this build) must always be reachable.
HWTEST_F(UserAuthEngineTest, GetUserAuthEngineReturnsNonNull, TestSize.Level0)
{
    // stable across calls (same static instance)
    EXPECT_EQ(&GetUserAuthEngine(), &GetUserAuthEngine());
}

// SetStatusCallback installs the engine lifecycle callback without
// throwing; the HDI variant reaches out to the HDI
// ServiceManager, which simply does not exist in the host test environment.
// Capture-free: the callback is stored on the engine singleton and may be
// invoked later from a worker thread, so it must not dangle onto test stack.
HWTEST_F(UserAuthEngineTest, SetStatusCallbackNoThrow, TestSize.Level0)
{
    EXPECT_NO_THROW(GetUserAuthEngine().SetStatusCallback([](bool running) { (void)running; }));
}

// When the HDI proxy is unreachable (GetHdiInstance() == nullptr),
// every engine method must return ENGINE_UNAVAILABLE — not GENERAL_ERROR — so
// callers (e.g. LoadModeHandlerDynamic::AnyUserHasPinCredential) keep the prior
// IS_PIN_ENROLLED value instead of treating "engine unavailable" as "no credential".
HWTEST_F(UserAuthEngineTest, ReturnsEngineUnavailableWhenEngineDown, TestSize.Level0)
{
    // Set(nullptr) puts the Holder in a "disabled" state: Get() then returns
    // nullptr instead of lazily recreating a mock, so HdiWrapper::GetHdiInstance()
    // yields nullptr and HdiEngineImpl::GetCredential returns ENGINE_UNAVAILABLE.
    MockIUserAuthInterface::Holder::GetInstance().Set(nullptr);
    std::vector<EngCredentialInfo> infos;
    EXPECT_EQ(GetUserAuthEngine().GetCredential(0, static_cast<int32_t>(AuthType::PIN), infos), ENGINE_UNAVAILABLE);
    // Rebuild the default mock so subsequent tests get a fresh, non-null instance.
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// The in-tree HDI engine denies lock-screen widget launches by default; the ext
// engine overrides this hook to apply its own policy.
HWTEST_F(UserAuthEngineTest, IsWidgetCallerAllowedOnLockScreenDefaultDenied, TestSize.Level0)
{
    EngCallerAuthInfo callerInfo { .callerName = "com.test.caller", .callerType = 0, .appId = "test_app_id" };
    EXPECT_FALSE(GetUserAuthEngine().IsWidgetCallerAllowedOnLockScreen(callerInfo));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

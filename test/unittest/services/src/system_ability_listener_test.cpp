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

#include "system_ability_listener_test.h"

#include "system_ability_listener.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void SystemAbilityListenerTest::SetUpTestCase()
{
}

void SystemAbilityListenerTest::TearDownTestCase()
{
}

void SystemAbilityListenerTest::SetUp()
{
}

void SystemAbilityListenerTest::TearDown()
{
}

HWTEST_F(SystemAbilityListenerTest, OnAddSystemAbilityTest001, TestSize.Level3)
{
    std::string name = "";
    int32_t systemAbilityId = 1;
    SystemAbilityListener listener(name, systemAbilityId, []() {}, []() {});

    std::string deviceId = "";
    EXPECT_NO_THROW(listener.OnAddSystemAbility(systemAbilityId, deviceId));
}

HWTEST_F(SystemAbilityListenerTest, OnAddSystemAbilityTest002, TestSize.Level3)
{
    std::string name = "";
    int32_t systemAbilityId = 1;
    SystemAbilityListener listener(name, systemAbilityId, []() {}, []() {});

    std::string deviceId = "";
    int32_t otherSystemAbilityId = 2;
    EXPECT_NO_THROW(listener.OnAddSystemAbility(otherSystemAbilityId, deviceId));
}

HWTEST_F(SystemAbilityListenerTest, OnRemoveSystemAbilityTest001, TestSize.Level3)
{
    std::string name = "";
    int32_t systemAbilityId = 1;
    SystemAbilityListener listener(name, systemAbilityId, []() {}, []() {});

    std::string deviceId = "";
    int32_t otherSystemAbilityId = 2;
    EXPECT_NO_THROW(listener.OnRemoveSystemAbility(otherSystemAbilityId, deviceId));
}

HWTEST_F(SystemAbilityListenerTest, OnRemoveSystemAbilityTest002, TestSize.Level3)
{
    std::string name = "";
    int32_t systemAbilityId = 1;
    SystemAbilityListener listener(name, systemAbilityId, []() {}, []() {});

    std::string deviceId = "";
    EXPECT_NO_THROW(listener.OnRemoveSystemAbility(systemAbilityId, deviceId));
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

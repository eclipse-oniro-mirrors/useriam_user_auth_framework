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

#include "ui_extension_ability_connection.h"

#include <future>

#include "mock_authentication.h"
#include "mock_context.h"
#include "mock_resource_node.h"
#include "mock_schedule_node.h"
#include "user_auth_callback_proxy.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UIExtensionAbilityConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void UIExtensionAbilityConnectionTest::SetUpTestCase()
{
}

void UIExtensionAbilityConnectionTest::TearDownTestCase()
{
}

void UIExtensionAbilityConnectionTest::SetUp()
{
}

void UIExtensionAbilityConnectionTest::TearDown()
{
}

HWTEST_F(UIExtensionAbilityConnectionTest, UIExtensionAbilityConnectionTestOnAbilityDisconnectDone, TestSize.Level0)
{
    auto connection = new UIExtensionAbilityConnection("connection");
    AppExecFwk::ElementName element;
    int32_t resultCode = 1;
    connection->OnAbilityDisconnectDone(element, resultCode);
}
}
}
}
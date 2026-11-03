/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "ability_manager_client.h"
#include "ui_extension_ability_connection.h"

#include <future>

#include "iam_callback_proxy.h"
#include "mock_authentication.h"
#include "mock_context.h"
#include "mock_remote_object.h"
#include "mock_resource_node.h"
#include "mock_schedule_node.h"
#include "mock_widget_schedule_node.h"
#include "widget_client.h"

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

HWTEST_F(UIExtensionAbilityConnectionTest, UIExtensionAbilityConnectionTestOnAbilityDisconnectDone_001, TestSize.Level0)
{
    auto connection = new UIExtensionAbilityConnection("connection");
    AppExecFwk::ElementName element;
    int32_t resultCode = 1;
    connection->OnAbilityDisconnectDone(element, resultCode);
    connection->ReleaseUIExtensionComponentInner();
    connection->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_NE(connection, nullptr);
}

HWTEST_F(UIExtensionAbilityConnectionTest, UIExtensionAbilityConnectionTestOnAbilityDisconnectDone_002, TestSize.Level0)
{
    auto connection = new UIExtensionAbilityConnection("connection");
    AppExecFwk::ElementName element;
    int32_t resultCode = 1;
    connection->isNormalEnd_ = false;
    connection->isConnectionRelease_ = true;
    connection->OnAbilityDisconnectDone(element, resultCode);
    connection->ReleaseUIExtensionComponentInner();
    connection->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_NE(connection, nullptr);
}

HWTEST_F(UIExtensionAbilityConnectionTest, UIExtensionAbilityConnectionTestOnAbilityDisconnectDone_003, TestSize.Level0)
{
    auto connection = new UIExtensionAbilityConnection("connection");
    AppExecFwk::ElementName element;
    int32_t resultCode = 1;
    connection->isNormalEnd_ = true;
    connection->isConnectionRelease_ = false;
    connection->OnAbilityDisconnectDone(element, resultCode);
    connection->ReleaseUIExtensionComponentInner();
    connection->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_NE(connection, nullptr);
}

HWTEST_F(UIExtensionAbilityConnectionTest, UIExtensionAbilityConnectionTestOnAbilityConnectDone, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    uint32_t onAbilityConnectDone = 1;
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillRepeatedly(
            [&onAbilityConnectDone](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_TRUE(reply.WriteInt32(SUCCESS));
                return GENERAL_ERROR;
            }
        );
    auto connection = new UIExtensionAbilityConnection("connection");
    AppExecFwk::ElementName element;
    int32_t resultCode = 0;
    connection->OnAbilityConnectDone(element, obj, resultCode);
    EXPECT_NE(connection, nullptr);
}

HWTEST_F(UIExtensionAbilityConnectionTest, UIExtensionAbilityConnectionTestDisconnectIsScopedToOwnContext,
    TestSize.Level0)
{
    constexpr uint64_t staleId = 31;
    constexpr uint64_t currentId = 32;
    auto &client = WidgetClient::Instance();
    client.Reset();

    auto currentSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    EXPECT_CALL(*currentSchedule, StopSchedule).Times(0);
    EXPECT_CALL(*currentSchedule, ClearSchedule).Times(0);
    auto staleSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    EXPECT_CALL(*staleSchedule, StopSchedule).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*staleSchedule, ClearSchedule).Times(1).WillOnce(Return(true));

    client.SetWidgetSchedule(currentId, currentSchedule);
    std::shared_ptr<WidgetScheduleNode> staleNode = staleSchedule;
    client.InsertScheduleNode(staleId, staleNode);

    auto connection = new UIExtensionAbilityConnection("connection", staleId);
    AppExecFwk::ElementName element;
    connection->OnAbilityDisconnectDone(element, 0);
    EXPECT_NE(client.GetScheduleNode(currentId), nullptr);
    EXPECT_EQ(client.GetScheduleNode(staleId), nullptr);

    ASSERT_TRUE(Mock::VerifyAndClearExpectations(currentSchedule.get()));
    EXPECT_CALL(*currentSchedule, StopSchedule).WillOnce(Return(true));
    EXPECT_CALL(*currentSchedule, ClearSchedule).WillOnce(Return(true));
    client.ClearSchedule(currentId);
    delete connection;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

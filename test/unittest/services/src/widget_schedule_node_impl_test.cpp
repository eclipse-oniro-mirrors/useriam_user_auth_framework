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

#include "widget_schedule_node_impl.h"
#include "widget_context.h"

#include <future>

#include "mock_widget_schedule_node_callback.h"
#include "mock_context.h"
#include "iam_ptr.h"
#include "relative_timer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
auto &timer = RelativeTimer::GetInstance();
}
static std::shared_ptr<WidgetScheduleNodeCallback> widgetContext = nullptr;

class WidgetScheduleNodeImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void WidgetScheduleNodeImplTest::SetUpTestCase()
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    std::shared_ptr<ContextCallback> callback = Common::MakeShared<MockContextCallback>();
    widgetContext = Common::MakeShared<WidgetContext>(contextId, para, callback, nullptr);
}

void WidgetScheduleNodeImplTest::TearDownTestCase()
{
}

void WidgetScheduleNodeImplTest::SetUp()
{
}

void WidgetScheduleNodeImplTest::TearDown()
{
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartSchedule, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    EXPECT_TRUE(schedule->StartSchedule());
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartAuthList, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::vector<AuthType> authTypeList = {AuthType::ALL, AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    EXPECT_TRUE(schedule->StartAuthList(authTypeList, true, AuthIntent::DEFAULT));
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStopAuthList, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::vector<AuthType> authTypeList = {AuthType::ALL, AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_TRUE(schedule->StopAuthList(authTypeList));
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplSuccessAuth, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::vector<AuthType> authTypeList = {AuthType::ALL, AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    schedule->StartAuthList(authTypeList, true, AuthIntent::DEFAULT);
    EXPECT_TRUE(schedule->SuccessAuth(AuthType::PIN));
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplNaviPinAuth, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    EXPECT_TRUE(schedule->NaviPinAuth());
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplWidgetParaInvalid, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    EXPECT_TRUE(schedule->WidgetParaInvalid());
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStopSchedule, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    EXPECT_TRUE(schedule->StopSchedule());
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplWidgetReload_0001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    uint32_t orientation = 1;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 1;
    AuthType rotateAuthType = PIN;
    EXPECT_TRUE(schedule->WidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType));
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplWidgetReload_0002, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    uint32_t orientation = 2;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 1;
    AuthType rotateAuthType = FINGERPRINT;
    EXPECT_TRUE(schedule->WidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType));
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplWidgetReload_0003, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    uint32_t orientation = 3;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 1;
    AuthType rotateAuthType = FACE;
    EXPECT_TRUE(schedule->WidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType));
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, OnWidgetReload_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    auto machine = schedule->MakeFiniteStateMachine();
    uint32_t event = 1;
    EXPECT_NO_THROW(schedule->OnWidgetReload(*machine, event));
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartDirectAuth_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    EXPECT_TRUE(schedule->StartDirectAuth());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartDirectAuth_002, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->machine_ = nullptr;
    EXPECT_FALSE(schedule->StartDirectAuth());
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartDirectAuth_003, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE};
    schedule->StartDirectAuth();
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, FailAuthClearsCorrectAuthType, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    std::vector<AuthType> authTypeList = {AuthType::FACE};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    
    EXPECT_CALL(*callback, FailAuth(AuthType::FACE)).Times(1);
    EXPECT_TRUE(schedule->FailAuth(AuthType::FACE));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, OnStartDirectAuth_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    auto machine = schedule->MakeFiniteStateMachine();
    uint32_t event = WidgetScheduleNode::E_START_DIRECT_AUTH;
    EXPECT_NO_THROW(schedule->OnStartDirectAuth(*machine, event));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, OnStartDirectAuth_002, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE};
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    auto machine = schedule->MakeFiniteStateMachine();
    uint32_t event = WidgetScheduleNode::E_START_DIRECT_AUTH;
    EXPECT_NO_THROW(schedule->OnStartDirectAuth(*machine, event));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_CompanionDeviceAuthSuccess_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_CALL(*callback, SuccessAuth(AuthType::COMPANION_DEVICE)).Times(1);
    EXPECT_TRUE(schedule->SuccessAuth(AuthType::COMPANION_DEVICE));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_CompanionDeviceAuthFail_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_CALL(*callback, FailAuth(AuthType::COMPANION_DEVICE)).Times(1);
    EXPECT_TRUE(schedule->FailAuth(AuthType::COMPANION_DEVICE));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_CompanionDeviceWithOtherAuth_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE, AuthType::PIN};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_CompanionDeviceCancel_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_TRUE(schedule->StopSchedule());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_StartDirectAuthWithRunningAuth_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE, AuthType::FACE};
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartDirectAuth();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_StartDirectAuthEmptyList_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    std::vector<AuthType> emptyAuthTypeList;
    schedule->StartAuthList(emptyAuthTypeList, false, AuthIntent::DEFAULT);
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartDirectAuth();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_OnFailAuthClearCorrectAuthType_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_CALL(*callback, FailAuth(AuthType::COMPANION_DEVICE)).Times(1);
    EXPECT_TRUE(schedule->FailAuth(AuthType::COMPANION_DEVICE));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_OnFailAuthWithMultipleTypes_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    std::vector<AuthType> authTypeList = {AuthType::FACE, AuthType::COMPANION_DEVICE};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_CALL(*callback, FailAuth(AuthType::FACE)).Times(1);
    EXPECT_TRUE(schedule->FailAuth(AuthType::FACE));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_DuplicateAuthTypeInStartAuth_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);

    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();

    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});

    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_MachineNullptrScenario_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->machine_ = nullptr;
    EXPECT_FALSE(schedule->StartSchedule());
    EXPECT_FALSE(schedule->StartDirectAuth());
    EXPECT_FALSE(schedule->StopSchedule());
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_StartScheduleWithNullCallback_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(nullptr);
    // Business logic allows starting schedule with null callback (callback check is deferred)
    EXPECT_TRUE(schedule->StartSchedule());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_OnWidgetParaInvalid_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    schedule->SetCallback(widgetContext);
    schedule->StartSchedule();
    EXPECT_TRUE(schedule->WidgetParaInvalid());
    widgetContext->LaunchWidget();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_WidgetReloadFail_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    std::vector<AuthType> authTypeList = {AuthType::PIN};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);

    uint32_t orientation = 2;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 0;
    AuthType rotateAuthType = PIN;

    // WidgetReload triggers state transition: AuthWidgetReloadInit first
    EXPECT_CALL(*callback, AuthWidgetReloadInit()).Times(AnyNumber());
    EXPECT_CALL(*callback, AuthWidgetReload(_, _, _, _)).WillOnce(Return(false));
    EXPECT_TRUE(schedule->WidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType));
    schedule->StopSchedule(); // Trigger E_CANCEL_AUTH to call AuthWidgetReload

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_EmptyAuthTypeList_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    std::vector<AuthType> emptyAuthTypeList;
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(emptyAuthTypeList, false, AuthIntent::DEFAULT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_FailAuthForFace_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();

    std::vector<AuthType> authTypeList = {AuthType::FACE};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);

    EXPECT_CALL(*callback, FailAuth(AuthType::FACE)).Times(1);
    EXPECT_TRUE(schedule->FailAuth(AuthType::FACE));

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_FailAuthForFingerprint_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();

    std::vector<AuthType> authTypeList = {AuthType::FINGERPRINT};
    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);

    EXPECT_CALL(*callback, FailAuth(AuthType::FINGERPRINT)).Times(1);
    EXPECT_TRUE(schedule->FailAuth(AuthType::FINGERPRINT));

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_ClearSchedule_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    EXPECT_CALL(*callback, LaunchWidget()).WillOnce(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*callback, ClearSchedule()).Times(1);
    EXPECT_TRUE(schedule->ClearSchedule());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_SendAuthTipInfo_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);
    std::vector<AuthType> authTypeList = {AuthType::PIN, AuthType::FACE};
    int32_t tipCode = TIP_CODE_FAIL;
    EXPECT_CALL(*callback, SendAuthTipInfo(_, _)).Times(2);
    schedule->SendAuthTipInfo(authTypeList, tipCode);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImpl_OnStartDirectAuthDuplicateCheck_001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    auto callback = std::make_shared<MockWidgetScheduleNodeCallback>();
    schedule->SetCallback(callback);

    std::vector<AuthType> authTypeList = {AuthType::COMPANION_DEVICE, AuthType::FACE};
    schedule->StartAuthList(authTypeList, false, AuthIntent::DEFAULT);

    EXPECT_CALL(*callback, ExecuteAuthList(_, _, _)).Times(1);
    schedule->StartDirectAuth();

    schedule->StartDirectAuth();

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

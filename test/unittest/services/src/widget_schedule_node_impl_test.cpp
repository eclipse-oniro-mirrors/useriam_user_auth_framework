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
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

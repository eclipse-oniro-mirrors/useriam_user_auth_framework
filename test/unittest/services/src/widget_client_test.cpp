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

#include "widget_client.h"
#include "widget_schedule_node_impl.h"

#include <future>
#include "iam_check.h"
#include "widget_json.h"
#include "widget_callback_interface.h"

#include "mock_authentication.h"
#include "mock_context.h"
#include "mock_resource_node.h"
#include "mock_schedule_node.h"
#include "schedule_node_impl.h"
#include "user_auth_callback_proxy.h"
#include "widget_schedule_node.h"
#include "widget_callback_proxy.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {

class WidgetClientTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void WidgetClientTest::SetUpTestCase()
{
}

void WidgetClientTest::TearDownTestCase()
{
}

void WidgetClientTest::SetUp()
{
}

void WidgetClientTest::TearDown()
{
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetWidgetSchedule, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    WidgetClient::Instance().SetWidgetSchedule(schedule);
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetWidgetContextId, TestSize.Level0)
{
    uint64_t contextId = 6;
    WidgetClient::Instance().SetWidgetContextId(contextId);
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetWidgetParam, TestSize.Level0)
{
    WidgetParam widgetParam;
    WidgetClient::Instance().SetWidgetParam(widgetParam);
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetWidgetCallback, TestSize.Level0)
{
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    WidgetClient::Instance().SetWidgetCallback(testCallback);
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetAuthTokenId, TestSize.Level0)
{
    uint32_t tokenId = 1;
    WidgetClient::Instance().SetAuthTokenId(tokenId);
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), tokenId);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_001, TestSize.Level0)
{
    std::string eventData = "";
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_002, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = "EVENT_AUTH_TYPE_READY";
    widgetNotice.typeList.push_back("pin");
    widgetNotice.typeList.push_back("face");
    widgetNotice.typeList.push_back("fingerprint");
    widgetNotice.typeList.push_back("all");
    widgetNotice.version = "1";
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_003, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = "EVENT_AUTH_USER_CANCEL";
    widgetNotice.typeList.push_back("pin");
    widgetNotice.typeList.push_back("face");
    widgetNotice.typeList.push_back("fingerprint");
    widgetNotice.typeList.push_back("all");
    widgetNotice.version = "1";
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_004, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = "EVENT_AUTH_USER_CANCEL";
    widgetNotice.typeList.push_back("all");
    widgetNotice.version = "1";
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_005, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = "EVENT_AUTH_USER_NAVIGATION";
    widgetNotice.typeList.push_back("pin");
    widgetNotice.typeList.push_back("face");
    widgetNotice.typeList.push_back("fingerprint");
    widgetNotice.typeList.push_back("all");
    widgetNotice.version = "1";
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_006, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = "aaaaa";
    widgetNotice.typeList.push_back("pin");
    widgetNotice.typeList.push_back("face");
    widgetNotice.typeList.push_back("fingerprint");
    widgetNotice.typeList.push_back("all");
    widgetNotice.version = "1";
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestReportWidgetResult_001, TestSize.Level0)
{
    int32_t result = 1;
    int32_t lockoutDuration = 1;
    int32_t remainAttempts = 1;
    WidgetClient::Instance().ReportWidgetResult(result, AuthType::FINGERPRINT, lockoutDuration, remainAttempts);
}

HWTEST_F(WidgetClientTest, WidgetClientTestReportWidgetResult_002, TestSize.Level0)
{
    int32_t result = 1;
    int32_t lockoutDuration = 1;
    int32_t remainAttempts = 1;
    WidgetClient::Instance().SetSensorInfo("Sensor");
    WidgetClient::Instance().ReportWidgetResult(result, AuthType::FINGERPRINT, lockoutDuration, remainAttempts);
}

HWTEST_F(WidgetClientTest, WidgetClientTestReportWidgetResult_003, TestSize.Level0)
{
    int32_t result = 1;
    int32_t lockoutDuration = 1;
    int32_t remainAttempts = 1;
    WidgetClient::Instance().Reset();
    WidgetClient::Instance().SetSensorInfo("Sensor");
    WidgetClient::Instance().ReportWidgetResult(result, AuthType::FINGERPRINT, lockoutDuration, remainAttempts);
}

HWTEST_F(WidgetClientTest, WidgetClientTestReportWidgetResult_004, TestSize.Level0)
{
    int32_t result = 1;
    int32_t lockoutDuration = 1;
    int32_t remainAttempts = 1;
    WidgetClient::Instance().Reset();
    MessageParcel data;
    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    sptr<WidgetCallbackInterface> testCallback = iface_cast<WidgetCallbackProxy>(obj);

    EXPECT_EQ(testCallback, nullptr);
    WidgetClient::Instance().SetWidgetCallback(testCallback);
    WidgetClient::Instance().ReportWidgetResult(result, AuthType::PIN, lockoutDuration, remainAttempts);
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetPinSubType, TestSize.Level0)
{
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_SIX);
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_NUMBER);
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_MIXED);
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_MAX);
    WidgetClient::Instance().SetPinSubType((PinSubType)123);
}
}
}
}
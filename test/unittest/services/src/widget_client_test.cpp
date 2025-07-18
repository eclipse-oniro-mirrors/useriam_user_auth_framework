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

#include <future>
#include "iam_callback_proxy.h"
#include "auth_common.h"
#include "iam_check.h"
#include "iam_ptr.h"
#include "widget_json.h"
#include "iwidget_callback.h"

#include "mock_authentication.h"
#include "mock_context.h"
#include "mock_resource_node.h"
#include "mock_schedule_node.h"
#include "mock_widget_schedule_node.h"
#include "mock_widget_callback_interface.h"
#include "schedule_node_impl.h"
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

    std::shared_ptr<WidgetScheduleNode> BuildSchedule();
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

std::shared_ptr<WidgetScheduleNode> WidgetClientTest::BuildSchedule()
{
    auto schedule = Common::MakeShared<MockWidgetScheduleNode>();
    EXPECT_NE(schedule, nullptr);
    EXPECT_CALL(*schedule, StartSchedule).WillRepeatedly(Return(true));
    EXPECT_CALL(*schedule, StopSchedule).WillRepeatedly(Return(true));
    EXPECT_CALL(*schedule, StartAuthList).WillRepeatedly(Return(true));
    EXPECT_CALL(*schedule, StopAuthList).WillRepeatedly(Return(true));
    EXPECT_CALL(*schedule, SuccessAuth).WillRepeatedly(Return(true));
    EXPECT_CALL(*schedule, NaviPinAuth).WillRepeatedly(Return(true));
    EXPECT_CALL(*schedule, WidgetReload).WillRepeatedly(Return(true));
    return schedule;
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetWidgetSchedule_0001, TestSize.Level0)
{
    auto schedule = BuildSchedule();
    WidgetClient::Instance().SetWidgetSchedule(schedule);
    EXPECT_NE(schedule, nullptr);
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetWidgetSchedule_0002, TestSize.Level0)
{
    std::shared_ptr<WidgetScheduleNode> nullSchedule(nullptr);
    WidgetClient::Instance().SetWidgetSchedule(nullSchedule);
    EXPECT_EQ(nullSchedule, nullptr);
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetWidgetParam, TestSize.Level0)
{
    WidgetParamInner widgetParam;
    WidgetClient::Instance().SetWidgetParam(widgetParam);
    EXPECT_EQ(widgetParam.title, "");
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetWidgetCallback, TestSize.Level0)
{
    sptr<IWidgetCallback> testCallback = nullptr;
    WidgetClient::Instance().SetWidgetCallback(testCallback);
    EXPECT_EQ(testCallback, nullptr);
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetAuthTokenId, TestSize.Level0)
{
    uint32_t tokenId = 1;
    WidgetClient::Instance().SetAuthTokenId(tokenId);
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), tokenId);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0001, TestSize.Level0)
{
    std::string eventData = "";
    WidgetClient::Instance().Reset();
    EXPECT_EQ(WidgetClient::Instance().OnNotice((NoticeType)0, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0002, TestSize.Level0)
{
    std::string eventData = "";
    WidgetClient::Instance().Reset();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0003, TestSize.Level0)
{
    std::string eventData = "invalid_json_string";
    WidgetClient::Instance().Reset();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0004, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0005, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = "INVALID_EVENT_AUTH_TYPE";
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0006, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_AUTH_READY;
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::GENERAL_ERROR);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0007, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_AUTH_READY;
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0008, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_AUTH_READY;
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0009, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_AUTH_READY;
    widgetNotice.typeList.push_back("all");
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0010, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_AUTH_READY;
    widgetNotice.typeList.push_back("pin");
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::FACE);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0011, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_AUTH_READY;
    widgetNotice.typeList.push_back("pin");
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0012, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_CANCEL_AUTH;
    widgetNotice.typeList.push_back("all");
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0013, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_CANCEL_AUTH;
    widgetNotice.typeList.push_back("pin");
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    authTypeList.emplace_back(AuthType::FACE);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0014, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_CANCEL_AUTH;
    widgetNotice.typeList.push_back("pin");
    widgetNotice.typeList.push_back("face");
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    authTypeList.emplace_back(AuthType::FACE);
    authTypeList.emplace_back(AuthType::FINGERPRINT);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0015, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_CANCEL_AUTH;
    widgetNotice.typeList.push_back("pin");
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0016, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_USER_NAVIGATION;
    widgetNotice.typeList.push_back("pin");
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::SUCCESS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestOnNotice_0017, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_CANCEL_AUTH;
    widgetNotice.typeList.push_back("all");
    widgetNotice.typeList.push_back("face");
    nlohmann::json root = widgetNotice;
    std::string eventData = root.dump();
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_EQ(WidgetClient::Instance().OnNotice(NoticeType::WIDGET_NOTICE, eventData), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(WidgetClientTest, WidgetClientTestReportWidgetResult_0001, TestSize.Level0)
{
    WidgetClient::Instance().Reset();
    WidgetClient::Instance().SetSensorInfo("fake senor info");
    WidgetClient::Instance().ReportWidgetResult(1, AuthType::FINGERPRINT, 1, 1, false);
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), 0);
}

HWTEST_F(WidgetClientTest, WidgetClientTestReportWidgetResult_0002, TestSize.Level0)
{
    WidgetClient::Instance().Reset();
    WidgetClient::Instance().ReportWidgetResult(1, AuthType::FINGERPRINT, 1, 1, false);
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), 0);
}

HWTEST_F(WidgetClientTest, WidgetClientTestReportWidgetResult_0003, TestSize.Level0)
{
    WidgetClient::Instance().Reset();
    WidgetClient::Instance().SetSensorInfo("fake senor info");
    WidgetClient::Instance().ReportWidgetResult(1, AuthType::PIN, 1, 1, false);
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), 0);
}

HWTEST_F(WidgetClientTest, WidgetClientTestReportWidgetResult_0004, TestSize.Level0)
{
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_NUMBER);
    WidgetClient::Instance().ReportWidgetResult(1, AuthType::PIN, 1, 1, false);
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), 0);
}

HWTEST_F(WidgetClientTest, WidgetClientTestReportWidgetResult_0005, TestSize.Level0)
{
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_NUMBER);
    sptr<MockIWidgetCallback> widgetCallback(new (std::nothrow) MockIWidgetCallback);
    EXPECT_NE(widgetCallback, nullptr);
    EXPECT_CALL(*widgetCallback, SendCommand);
    WidgetClient::Instance().SetWidgetCallback(widgetCallback);
    WidgetClient::Instance().ReportWidgetResult(1, AuthType::PIN, 1, 1, false);
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), 0);
}

HWTEST_F(WidgetClientTest, WidgetClientTestForceStopAuth_0001, TestSize.Level0)
{
    WidgetClient::Instance().Reset();
    WidgetClient::Instance().ForceStopAuth();
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), 0);
}

HWTEST_F(WidgetClientTest, WidgetClientTestForceStopAuth_0002, TestSize.Level0)
{
    uint64_t contextId = 6;
    WidgetClient::Instance().Reset();
    WidgetClient::Instance().SetWidgetContextId(contextId);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    WidgetClient::Instance().ForceStopAuth();
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), 0);
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetPinSubType, TestSize.Level0)
{
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_SIX);
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_NUMBER);
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_MIXED);
    WidgetClient::Instance().SetPinSubType(PinSubType::PIN_MAX);
    WidgetClient::Instance().SetPinSubType((PinSubType)123);
    EXPECT_EQ(WidgetClient::Instance().GetAuthTokenId(), 0);
}

HWTEST_F(WidgetClientTest, WidgetClientTestProcessNotice_001, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_WIDGET_PARA_INVALID;
    widgetNotice.typeList.push_back("pin");
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_NO_THROW(WidgetClient::Instance().ProcessNotice(widgetNotice, authTypeList));
}

HWTEST_F(WidgetClientTest, WidgetClientTestProcessNotice_002, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_END;
    widgetNotice.typeList.push_back("pin");
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_NO_THROW(WidgetClient::Instance().ProcessNotice(widgetNotice, authTypeList));
}

HWTEST_F(WidgetClientTest, WidgetClientTestProcessNotice_003, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_RELOAD;
    widgetNotice.typeList.push_back("pin");
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_NO_THROW(WidgetClient::Instance().ProcessNotice(widgetNotice, authTypeList));
}

HWTEST_F(WidgetClientTest, WidgetClientTestProcessNotice_004, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_RELOAD;
    widgetNotice.typeList.push_back("pin");
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::ALL);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_NO_THROW(WidgetClient::Instance().ProcessNotice(widgetNotice, authTypeList));
}

HWTEST_F(WidgetClientTest, WidgetClientTestProcessNotice_005, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = NOTICE_EVENT_RELOAD;
    widgetNotice.typeList.push_back("pin");
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::ALL);
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_NO_THROW(WidgetClient::Instance().ProcessNotice(widgetNotice, authTypeList));
}

HWTEST_F(WidgetClientTest, WidgetClientTestProcessNotice_006, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = EVENT_AUTH_WIDGET_LOADED;
    widgetNotice.typeList.push_back("pin");
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_NO_THROW(WidgetClient::Instance().ProcessNotice(widgetNotice, authTypeList));
}

HWTEST_F(WidgetClientTest, WidgetClientTestProcessNotice_007, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = EVENT_AUTH_WIDGET_RELEASED;
    widgetNotice.typeList.push_back("pin");
    WidgetClient::Instance().Reset();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(AuthType::PIN);
    WidgetClient::Instance().SetAuthTypeList(authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(BuildSchedule());
    EXPECT_NO_THROW(WidgetClient::Instance().ProcessNotice(widgetNotice, authTypeList));
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetPinSubType_001, TestSize.Level0)
{
    WidgetClient::Instance().Reset();
    EXPECT_NO_THROW(WidgetClient::Instance().SetPinSubType(PinSubType::PIN_FOUR));
}

HWTEST_F(WidgetClientTest, WidgetClientTestSetPinSubType_002, TestSize.Level0)
{
    WidgetClient::Instance().Reset();
    EXPECT_NO_THROW(WidgetClient::Instance().SetPinSubType(PinSubType::PIN_PATTERN));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

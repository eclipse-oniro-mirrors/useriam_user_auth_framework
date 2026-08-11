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
#include "widget_json.h"
#include "context_factory.h"

#include <future>
#include <gmock/gmock.h>

#include "iam_common_defines.h"
#include "user_auth_common_defines.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetJsonTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void WidgetJsonTest::SetUpTestCase()
{
}

void WidgetJsonTest::TearDownTestCase()
{
}

void WidgetJsonTest::SetUp()
{
}

void WidgetJsonTest::TearDown()
{
}

struct TestAuthProfile {
    int32_t pinSubType {0};
    std::string sensorInfo;
    int32_t remainTimes {0};
    int32_t freezingTime {0};
};

void CreatePara(ContextFactory::AuthWidgetContextPara &para, WindowModeType windowModeType)
{
    para.widgetParam.title = "widgetParam";
    para.widgetParam.windowMode = windowModeType;
    para.widgetParam.navigationButtonText = "navigationButtonText";
    ContextFactory::AuthProfile authProfile;
    para.authProfileMap.insert(pair<AuthType, ContextFactory::AuthProfile>(ALL, authProfile));
    para.authProfileMap.insert(pair<AuthType, ContextFactory::AuthProfile>(PIN, authProfile));
    para.authProfileMap.insert(pair<AuthType, ContextFactory::AuthProfile>(FACE, authProfile));
    para.authProfileMap.insert(pair<AuthType,
    ContextFactory::AuthProfile>(FINGERPRINT, authProfile));
}

HWTEST_F(WidgetJsonTest, WidgetJsonStr2AuthType_001, TestSize.Level0)
{
    std::string strAt = "pin";
    EXPECT_EQ(Str2AuthType(strAt), PIN);
}

HWTEST_F(WidgetJsonTest, WidgetJsonStr2AuthType_002, TestSize.Level0)
{
    std::string strAt = "fingerprint";
    EXPECT_EQ(Str2AuthType(strAt), FINGERPRINT);
}

HWTEST_F(WidgetJsonTest, WidgetJsonStr2AuthType_003, TestSize.Level0)
{
    std::string strAt = "face";
    EXPECT_EQ(Str2AuthType(strAt), FACE);
}

HWTEST_F(WidgetJsonTest, WidgetJsonStr2AuthType_004, TestSize.Level0)
{
    std::string strAt = "all";
    EXPECT_EQ(Str2AuthType(strAt), ALL);
}

HWTEST_F(WidgetJsonTest, WidgetJsonStr2AuthType_005, TestSize.Level0)
{
    std::string strAt = "asdf";
    EXPECT_EQ(Str2AuthType(strAt), INVALID_AUTH_TYPE);
}

HWTEST_F(WidgetJsonTest, WidgetJsonStr2AuthType_006, TestSize.Level0)
{
    std::string strAt = "privatePin";
    EXPECT_EQ(Str2AuthType(strAt), PRIVATE_PIN);
}

HWTEST_F(WidgetJsonTest, WidgetJsonStr2AuthType_007, TestSize.Level0)
{
    std::string strAt = "enterpriseAccount";
    EXPECT_EQ(Str2AuthType(strAt), PIN);
}

HWTEST_F(WidgetJsonTest, WidgetJsonAuthType2Str_001, TestSize.Level0)
{
    AuthType authType = static_cast<AuthType>(100);
    std::string type = AuthType2Str(authType);
    EXPECT_EQ(type, "");
}

HWTEST_F(WidgetJsonTest, WidgetJsonAuthType2Str_002, TestSize.Level0)
{
    std::string type = AuthType2Str(PRIVATE_PIN);
    EXPECT_EQ(type, "privatePin");
}

HWTEST_F(WidgetJsonTest, WidgetJsonAuthType2Str_003, TestSize.Level0)
{
    std::string type = AuthType2Str(PIN);
    EXPECT_EQ(type, "pin");
}

HWTEST_F(WidgetJsonTest, WidgetJsonAuthType2Str_004, TestSize.Level0)
{
    std::string type = AuthType2Str(FACE);
    EXPECT_EQ(type, "face");
}

HWTEST_F(WidgetJsonTest, WidgetJsonAuthType2Str_005, TestSize.Level0)
{
    std::string type = AuthType2Str(FINGERPRINT);
    EXPECT_EQ(type, "fingerprint");
}

HWTEST_F(WidgetJsonTest, WidgetJsonAuthType2Str_006, TestSize.Level0)
{
    std::string type = AuthType2Str(ALL);
    EXPECT_EQ(type, "all");
}

HWTEST_F(WidgetJsonTest, WidgetJsonAuthType2Str_007, TestSize.Level0)
{
    const int32_t enterpriseAccount = 1024;
    std::string type = AuthType2Str(static_cast<AuthType>(enterpriseAccount));
    EXPECT_EQ(type, "enterpriseAccount");
}

HWTEST_F(WidgetJsonTest, WidgetJsonWinModeType2Str_001, TestSize.Level0)
{
    EXPECT_EQ(WinModeType2Str(DIALOG_BOX), "DIALOG_BOX");
}

HWTEST_F(WidgetJsonTest, WidgetJsonWinModeType2Str_002, TestSize.Level0)
{
    EXPECT_EQ(WinModeType2Str(FULLSCREEN), "FULLSCREEN");
}

HWTEST_F(WidgetJsonTest, WidgetJsonPinSubType2Str_001, TestSize.Level0)
{
    EXPECT_EQ(PinSubType2Str(PinSubType::PIN_SIX), "PIN_SIX");
}

HWTEST_F(WidgetJsonTest, WidgetJsonPinSubType2Str_002, TestSize.Level0)
{
    EXPECT_EQ(PinSubType2Str(PinSubType::PIN_NUMBER), "PIN_NUMBER");
}

HWTEST_F(WidgetJsonTest, WidgetJsonPinSubType2Str_003, TestSize.Level0)
{
    EXPECT_EQ(PinSubType2Str(PinSubType::PIN_MIXED), "PIN_MIXED");
}

HWTEST_F(WidgetJsonTest, WidgetJsonPinSubType2Str_004, TestSize.Level0)
{
    EXPECT_EQ(PinSubType2Str(PinSubType::PIN_FOUR), "PIN_FOUR");
}

HWTEST_F(WidgetJsonTest, WidgetJsonPinSubType2Str_005, TestSize.Level0)
{
    EXPECT_EQ(PinSubType2Str(PinSubType::PIN_PATTERN), "PIN_PATTERN");
}

HWTEST_F(WidgetJsonTest, WidgetJsonPinSubType2Str_006, TestSize.Level0)
{
    EXPECT_EQ(PinSubType2Str(PinSubType::PIN_MAX), "PIN_MAX");
}

HWTEST_F(WidgetJsonTest, WidgetJsonGetFollowCallerList, TestSize.Level0)
{
    nlohmann::json jsonBuf;
    std::vector<std::string> processName;
    EXPECT_EQ(GetFollowCallerList(jsonBuf, processName), false);
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_001, TestSize.Level0)
{
    WidgetCommand widgetCommand;
    widgetCommand.widgetContextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    CreatePara(para, DIALOG_BOX);
    widgetCommand.title = para.widgetParam.title;
    widgetCommand.windowModeType = WinModeType2Str(para.widgetParam.windowMode);
    widgetCommand.navigationButtonText = para.widgetParam.navigationButtonText;
    auto it = para.authProfileMap.find(AuthType::PIN);
    if (it != para.authProfileMap.end()) {
        widgetCommand.pinSubType = PinSubType2Str(static_cast<PinSubType>(it->second.pinSubType));
    }
    std::vector<std::string> typeList;
    for (auto &item : para.authProfileMap) {
        auto &at = item.first;
        auto &profile = item.second;
        typeList.push_back(AuthType2Str(at));
        WidgetCommand::Cmd cmd {
            .event = CMD_NOTIFY_AUTH_START,
            .version = "1",
            .type = AuthType2Str(at)
        };
        cmd.result = PIN_EXPIRED;
        if (at == AuthType::FINGERPRINT && !profile.sensorInfo.empty()) {
            cmd.sensorInfo = profile.sensorInfo;
        }
        cmd.remainAttempts = profile.remainTimes;
        cmd.lockoutDuration = profile.freezingTime;
        widgetCommand.cmdList.push_back(cmd);
    }
    widgetCommand.typeList = typeList;
    nlohmann::json root = widgetCommand;
    std::string cmdData = root.dump();
    auto result = nlohmann::json::parse(cmdData.c_str());
    auto widgetContextId = result["widgetContextId"];
    EXPECT_EQ(widgetContextId, 1);
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_002, TestSize.Level0)
{
    WidgetCommand widgetCommand;
    widgetCommand.widgetContextId = 1;
    widgetCommand.pinSubType = "pinSubType";
    ContextFactory::AuthWidgetContextPara para;
    CreatePara(para, FULLSCREEN);
    widgetCommand.title = para.widgetParam.title;
    std::vector<std::string> typeList;
    for (auto &item : para.authProfileMap) {
        auto &at = item.first;
        typeList.push_back(AuthType2Str(at));
        WidgetCommand::Cmd cmd {
            .event = CMD_NOTIFY_AUTH_RESULT,
            .version = "1",
            .type = AuthType2Str(at)
        };
        cmd.sensorInfo = "sensorInfo";
        cmd.remainAttempts = -1;
        cmd.lockoutDuration = -1;
        widgetCommand.cmdList.push_back(cmd);
    }
    widgetCommand.typeList = typeList;
    nlohmann::json root = widgetCommand;
    std::string cmdData = root.dump();
    auto result = nlohmann::json::parse(cmdData.c_str());
    auto pinSubType = result["pinSubType"];
    EXPECT_EQ(pinSubType, "pinSubType");
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_003, TestSize.Level0)
{
    WidgetCmdParameters widgetCmdParameters;
    widgetCmdParameters.uiExtensionType = "sysDialog/userAuth";
    widgetCmdParameters.focusState = 0;
    widgetCmdParameters.useriamCmdData.widgetContextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    CreatePara(para, NONE_INTERRUPTION_DIALOG_BOX);
    widgetCmdParameters.useriamCmdData.title = para.widgetParam.title;
    widgetCmdParameters.useriamCmdData.windowModeType = WinModeType2Str(para.widgetParam.windowMode);
    widgetCmdParameters.useriamCmdData.navigationButtonText = para.widgetParam.navigationButtonText;
    auto it = para.authProfileMap.find(AuthType::PIN);
    if (it != para.authProfileMap.end()) {
        widgetCmdParameters.useriamCmdData.pinSubType = PinSubType2Str(static_cast<PinSubType>(it->second.pinSubType));
    }
    std::vector<std::string> typeList;
    for (auto &item : para.authProfileMap) {
        auto &at = item.first;
        auto &profile = item.second;
        typeList.push_back(AuthType2Str(at));
        WidgetCommand::Cmd cmd {
            .event = CMD_NOTIFY_AUTH_START,
            .version = "1",
            .type = AuthType2Str(at)
        };
        if (at == AuthType::FINGERPRINT && !profile.sensorInfo.empty()) {
            cmd.sensorInfo = profile.sensorInfo;
        }
        cmd.remainAttempts = profile.remainTimes;
        cmd.lockoutDuration = profile.freezingTime;
        widgetCmdParameters.useriamCmdData.cmdList.push_back(cmd);
    }
    widgetCmdParameters.useriamCmdData.typeList = typeList;
    nlohmann::json root = widgetCmdParameters;
    std::string cmdData = root.dump();
    auto result = nlohmann::json::parse(cmdData.c_str());
    auto uiExtensionType = result["ability.want.params.uiExtensionType"];
    EXPECT_EQ(uiExtensionType, "sysDialog/userAuth");
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_004, TestSize.Level0)
{
    WidgetCmdParameters widgetCmdParameters;
    widgetCmdParameters.uiExtensionType = "sysDialog/userAuth";
    widgetCmdParameters.focusState = 1;
    widgetCmdParameters.useriamCmdData.widgetContextId = 1;
    widgetCmdParameters.useriamCmdData.pinSubType = "pinSubType";
    ContextFactory::AuthWidgetContextPara para;
    CreatePara(para, DIALOG_BOX);
    widgetCmdParameters.useriamCmdData.title = para.widgetParam.title;
    std::vector<std::string> typeList;
    for (auto &item : para.authProfileMap) {
        auto &at = item.first;
        typeList.push_back(AuthType2Str(at));
        WidgetCommand::Cmd cmd {
            .event = CMD_NOTIFY_AUTH_RESULT,
            .version = "1",
            .type = AuthType2Str(at)
        };
        WidgetCommand::Cmd cmd1 {
            .event = CMD_NOTIFY_AUTH_TIP,
            .version = "1",
            .type = AuthType2Str(at)
        };
        cmd.sensorInfo = "sensorInfo";
        widgetCmdParameters.useriamCmdData.cmdList.push_back(cmd);
        widgetCmdParameters.useriamCmdData.cmdList.push_back(cmd1);
    }
    widgetCmdParameters.useriamCmdData.typeList = typeList;
    nlohmann::json root = widgetCmdParameters;
    std::string cmdData = root.dump();
    auto result = nlohmann::json::parse(cmdData.c_str());
    auto uiExtensionType = result["ability.want.params.uiExtensionType"];
    EXPECT_EQ(uiExtensionType, "sysDialog/userAuth");
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_005, TestSize.Level0)
{
    WidgetNotice widgetNotice;
    widgetNotice.widgetContextId = 1;
    widgetNotice.event = CMD_NOTIFY_AUTH_START;
    widgetNotice.typeList.push_back("pin");
    widgetNotice.typeList.push_back("face");
    widgetNotice.typeList.push_back("fingerprint");
    widgetNotice.typeList.push_back("all");
    widgetNotice.version = "1";
    auto authTypeList = widgetNotice.AuthTypeList();
    EXPECT_EQ(authTypeList[0], AuthType::PIN);
    nlohmann::json root = widgetNotice;
    std::string cmdData = root.dump();
    auto result = nlohmann::json::parse(cmdData.c_str());
    auto version = result["version"];
    EXPECT_EQ(version, "1");
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_006, TestSize.Level0)
{
    auto root = nlohmann::json::parse("", nullptr, false);
    WidgetNotice notice = root.get<WidgetNotice>();
    EXPECT_EQ(notice.widgetContextId, static_cast<uint64_t>(0));
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_007, TestSize.Level0)
{
    const std::string data = "{\"widgetContextId\":\"1\", \"event\":1, \"version\":1}";
    auto root = nlohmann::json::parse(data, nullptr, false);
    WidgetNotice notice = root.get<WidgetNotice>();
    EXPECT_EQ(notice.widgetContextId, static_cast<uint64_t>(0));
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_008, TestSize.Level0)
{
    const std::string data = "{\"widgetContextId\":1, \"event\":\"EVENT_AUTH_TYPE_READY\", \"version\":\"1\"}";
    auto root = nlohmann::json::parse(data, nullptr, false);
    WidgetNotice notice = root.get<WidgetNotice>();
    EXPECT_EQ(notice.widgetContextId, static_cast<uint64_t>(1));
    EXPECT_EQ(notice.event, "EVENT_AUTH_TYPE_READY");
    EXPECT_EQ(notice.version, "1");
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_009, TestSize.Level0)
{
    auto root = nlohmann::json::parse("{\"payload\":123}", nullptr, false);
    WidgetNotice notice = root.get<WidgetNotice>();
    EXPECT_EQ(notice.typeList.size(), static_cast<size_t>(0));
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_010, TestSize.Level0)
{
    auto root = nlohmann::json::parse("{\"payload\":{\"type\":123}}", nullptr, false);
    WidgetNotice notice = root.get<WidgetNotice>();
    EXPECT_EQ(notice.typeList.size(), static_cast<size_t>(0));
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_011, TestSize.Level0)
{
    auto root = nlohmann::json::parse("{\"payload\":{\"type\":[\"pin\", 123]}}", nullptr, false);
    WidgetNotice notice = root.get<WidgetNotice>();
    EXPECT_EQ(notice.typeList.size(), static_cast<size_t>(0));
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_012, TestSize.Level0)
{
    auto root = nlohmann::json::parse("{\"payload\":{\"type\":[\"pin\"]}}", nullptr, false);
    WidgetNotice notice = root.get<WidgetNotice>();
    EXPECT_EQ(notice.typeList.size(), static_cast<size_t>(1));
    EXPECT_EQ(notice.typeList[0], "pin");
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_013, TestSize.Level0)
{
    auto root = nlohmann::json::parse("{\"payload\":{\"endAfterFirstFail\":123}}", nullptr, false);
    WidgetNotice notice = root.get<WidgetNotice>();
    EXPECT_EQ(notice.endAfterFirstFail, false);
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_014, TestSize.Level0)
{
    auto root = nlohmann::json::parse("{\"payload\":{\"endAfterFirstFail\":true}}", nullptr, false);
    WidgetNotice notice = root.get<WidgetNotice>();
    EXPECT_EQ(notice.endAfterFirstFail, true);
}

HWTEST_F(WidgetJsonTest, WidgetJsonto_json_015, TestSize.Level0)
{
    WidgetCmdParameters widgetCmdParameters;
    widgetCmdParameters.uiExtensionType = "sysDialog/userAuth";
    widgetCmdParameters.focusState = 1;
    widgetCmdParameters.useriamCmdData.widgetContextId = 1;
    widgetCmdParameters.useriamCmdData.pinSubType = "pinSubType";
    ContextFactory::AuthWidgetContextPara para;
    CreatePara(para, DIALOG_BOX);
    widgetCmdParameters.useriamCmdData.title = para.widgetParam.title;
    std::vector<std::string> typeList;
    for (auto &item : para.authProfileMap) {
        auto &at = item.first;
        typeList.push_back(AuthType2Str(at));
        WidgetCommand::Cmd cmd {
            .event = CMD_NOTIFY_AUTH_TIP,
            .version = "1",
            .type = AuthType2Str(at)
        };
        cmd.sensorInfo = "sensorInfo";
        widgetCmdParameters.useriamCmdData.cmdList.push_back(cmd);
    }
    widgetCmdParameters.useriamCmdData.typeList = typeList;
    nlohmann::json root = widgetCmdParameters;
    std::string cmdData = root.dump();
    auto result = nlohmann::json::parse(cmdData.c_str());
    auto uiExtensionType = result["ability.want.params.uiExtensionType"];
    EXPECT_EQ(uiExtensionType, "sysDialog/userAuth");
}

HWTEST_F(WidgetJsonTest, WidgetJsonStr2AuthType_CompanionDevice_001, TestSize.Level0)
{
    std::string strAt = "companionDevice";
    EXPECT_EQ(Str2AuthType(strAt), AuthType::COMPANION_DEVICE);
}

HWTEST_F(WidgetJsonTest, WidgetJsonAuthType2Str_CompanionDevice_001, TestSize.Level0)
{
    AuthType authType = AuthType::COMPANION_DEVICE;
    std::string type = AuthType2Str(authType);
    EXPECT_EQ(type, "companionDevice");
}

HWTEST_F(WidgetJsonTest, WidgetJsonAuthTypeRoundTrip_CompanionDevice_001, TestSize.Level0)
{
    AuthType authType = AuthType::COMPANION_DEVICE;
    std::string typeStr = AuthType2Str(authType);
    AuthType convertedAuthType = Str2AuthType(typeStr);
    EXPECT_EQ(convertedAuthType, AuthType::COMPANION_DEVICE);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
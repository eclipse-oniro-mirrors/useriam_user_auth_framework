/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <map>
#include <fstream>
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "directory_ex.h"
#include "user_auth_common_defines.h"
#include "config_policy_utils.h"
#include "widget_json.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_WIDGET_JSON

namespace OHOS {
namespace UserIam {
namespace UserAuth {

const std::string AUTH_TYPE_PIN = "pin";
const std::string AUTH_TYPE_FACE = "face";
const std::string AUTH_TYPE_FINGER_PRINT = "fingerprint";
const std::string AUTH_TYPE_ALL = "all";
const std::string AUTH_TYPE_PRIVATE_PIN = "privatePin";
const std::string AUTH_TYPE_COMPANION_DEVICE = "companionDevice";

const std::string WINDOW_MODE_DIALOG = "DIALOG_BOX";
const std::string WINDOW_MODE_FULLSCREEN = "FULLSCREEN";
const std::string WINDOW_MODE_NONE_INTERRUPTION_DIALOG_BOX = "NONE_INTERRUPTION_DIALOG_BOX";

const std::string PIN_SUB_TYPE_SIX = "PIN_SIX";
const std::string PIN_SUB_TYPE_NUM = "PIN_NUMBER";
const std::string PIN_SUB_TYPE_MIX = "PIN_MIXED";
const std::string PIN_SUB_TYPE_FOUR = "PIN_FOUR";
const std::string PIN_SUB_TYPE_PATTERN = "PIN_PATTERN";
const std::string PIN_SUB_TYPE_MAX = "PIN_MAX";

const std::string JSON_AUTH_TYPE = "type";
const std::string JSON_WIDGET_CTX_ID = "widgetContextId";
const std::string JSON_WIDGET_CTX_ID_STR = "widgetContextIdStr";
const std::string JSON_AUTH_EVENT = "event";
const std::string JSON_AUTH_VERSION = "version";
const std::string JSON_AUTH_PAYLOAD = "payload";
const std::string JSON_AUTH_END_AFTER_FIRST_FAIL = "endAfterFirstFail";
const std::string JSON_AUTH_INTENT = "authIntent";
const std::string JSON_AUTH_TIP_CODE = "tipCode";
const std::string JSON_ORIENTATION = "orientation";
const std::string JSON_NEED_ROTATE = "needRotate";
const std::string JSON_ALREADY_LOAD = "alreadyLoad";
const std::string JSON_LOCKOUT_DURATION = "lockoutDuration";
const std::string JSON_REMAIN_ATTEMPTS = "remainAttempts";
const std::string JSON_AUTH_RESULT = "result";
const std::string JSON_SENSOR_INFO = "sensorInfo";
const std::string JSON_AUTH_TIP_TYPE = "tipType";
const std::string JSON_AUTH_TIP_INFO = "tipInfo";
const std::string JSON_AUTH_TITLE = "title";
const std::string JSON_AUTH_CMD = "cmd";
const std::string JSON_AUTH_PIN_SUB_TYPE = "pinSubType";
const std::string JSON_AUTH_WINDOW_MODE = "windowModeType";
const std::string JSON_AUTH_NAVI_BTN_TEXT = "navigationButtonText";
const std::string JSON_WIDGET_IS_RELOAD = "isReload";
const std::string JSON_WIDGET_ROTATE_AUTH_TYPE = "rotateAuthType";
const std::string JSON_WIDGET_CALLING_PROCESS_NAME = "callingProcessName";
const std::string JSON_WIDGET_CALLING_APP_ID = "callingAppID";
const std::string JSON_WIDGET_USER_ID = "userId";
const std::string JSON_WIDGET_SKIP_LOCKED_BIOMETRIC_AUTH = "skipLockedBiometricAuth";

const std::string JSON_UI_EXTENSION_TYPE = "ability.want.params.uiExtensionType";
const std::string JSON_UI_EXT_NODE_ANGLE = "ability.want.params.uiExtNodeAngle";
const std::string JSON_USER_IAM_CMD_DATA = "useriamCmdData";
const std::string JSON_SYS_DIALOG_ZORDER = "sysDialogZOrder";
const std::string JSON_IS_ENABLE_ROTATE = "isEnableRotate";
const std::string JSON_FOCUS_STATE = "focusState";

const std::string JSON_CHALLENGE = "challenge";
const std::string JSON_CALLER_BUNDLE_NAME = "callingBundleName";
const std::string JSON_CMD_EXTRA_INFO = "extraInfo";

constexpr const char *AUTH_WIDGE_CONFIG_SUFFIX = "etc/auth_widget/auth_widget_config.json";
const std::string SHWO_WITH_LEVEL_2_WINDOW = "show_with_level_2_window";
const std::string FOLLOW_CALLER_WINDOW_WHEN_FOLDED = "follow_caller_window_when_folded";
const std::string SCENEBOARD_BUNDLE_NAME = "sceneboard_bundle_name";
const std::string SCENEBOARD_ABILITY_NAME = "sceneboard_ability_name";
const std::string ALWAYS_SUPPORT_FOLLOW_CALLER_UI = "always_support_follow_caller_ui";

const uint32_t DISABLE_ROTATE = 0;
const uint32_t MAX_ERR_BUF_LEN = 256;

namespace {
void GetJsonPayload(nlohmann::json &jsonPayload, const WidgetCommand::Cmd &cmd)
{
    jsonPayload[JSON_AUTH_TYPE] = cmd.type;
    if (cmd.lockoutDuration != -1) {
        jsonPayload[JSON_LOCKOUT_DURATION] = cmd.lockoutDuration;
    }
    if (cmd.remainAttempts != -1) {
        jsonPayload[JSON_REMAIN_ATTEMPTS] = cmd.remainAttempts;
    }
    if (cmd.event == CMD_NOTIFY_AUTH_RESULT || cmd.result == PIN_EXPIRED) {
        jsonPayload[JSON_AUTH_RESULT] = cmd.result;
    }
    if (cmd.event == CMD_NOTIFY_AUTH_TIP) {
        jsonPayload[JSON_AUTH_TIP_TYPE] = cmd.tipType;
        jsonPayload[JSON_AUTH_TIP_INFO] = cmd.tipInfo;
    }
    if (!cmd.sensorInfo.empty()) {
        jsonPayload[JSON_SENSOR_INFO] = cmd.sensorInfo;
    }
    auto jsonCmdExtraInfo = nlohmann::json({{JSON_CHALLENGE, cmd.extraInfo.challenge},
        {JSON_CALLER_BUNDLE_NAME, cmd.extraInfo.callingBundleName}});
    jsonPayload[JSON_CMD_EXTRA_INFO] = jsonCmdExtraInfo;
}

void GetJsonCmd(nlohmann::json &jsonCommand, const WidgetCommand &command)
{
    std::vector<nlohmann::json> jsonCmdList;
    for (auto &cmd : command.cmdList) {
        auto jsonCmd = nlohmann::json({{JSON_AUTH_EVENT, cmd.event},
            {JSON_AUTH_VERSION, cmd.version}
        });
        nlohmann::json jsonPayload;
        GetJsonPayload(jsonPayload, cmd);
        jsonCmd[JSON_AUTH_PAYLOAD] = jsonPayload;
        jsonCmdList.push_back(jsonCmd);
    }

    jsonCommand = nlohmann::json({{JSON_WIDGET_CTX_ID, command.widgetContextId},
        {JSON_AUTH_TYPE, command.typeList},
        {JSON_AUTH_TITLE, command.title},
        {JSON_AUTH_CMD, jsonCmdList},
        {JSON_WIDGET_CTX_ID_STR, command.widgetContextIdStr}
    });
    if (command.pinSubType != "") {
        jsonCommand[JSON_AUTH_PIN_SUB_TYPE] = command.pinSubType;
    }
    if (command.windowModeType != "") {
        jsonCommand[JSON_AUTH_WINDOW_MODE] = command.windowModeType;
    }
    if (command.navigationButtonText != "") {
        jsonCommand[JSON_AUTH_NAVI_BTN_TEXT] = command.navigationButtonText;
    }
    jsonCommand[JSON_WIDGET_IS_RELOAD] = command.isReload;
    jsonCommand[JSON_WIDGET_ROTATE_AUTH_TYPE] = command.rotateAuthType;
    jsonCommand[JSON_WIDGET_CALLING_APP_ID] = command.callingAppID;
    jsonCommand[JSON_WIDGET_CALLING_PROCESS_NAME] = command.callingProcessName;
    jsonCommand[JSON_WIDGET_USER_ID] = command.userId;
    jsonCommand[JSON_WIDGET_SKIP_LOCKED_BIOMETRIC_AUTH] = command.skipLockedBiometricAuth;
}

bool ReadFileIntoJson(const std::string &filePath, nlohmann::json &jsonBuf)
{
    IAM_LOGI("ReadFileIntoJson entry");
    std::string realPath;
    if (!PathToRealPath(filePath, realPath)) {
        IAM_LOGE("Path to realPath failed");
        return false;
    }

    char errBuf[MAX_ERR_BUF_LEN];
    errBuf[0] = '\0';
    std::fstream in;
    in.open(realPath, std::ios_base::in);
    if (!in.is_open()) {
        strerror_r(errno, errBuf, sizeof(errBuf));
        IAM_LOGE("file open failed due to %{public}s, errno:%{public}d", errBuf, errno);
        return false;
    }

    in.seekg(0, std::ios::end);
    int64_t size = in.tellg();
    if (size <= 0) {
        IAM_LOGE("file empty, errno:%{public}d", errno);
        in.close();
        return false;
    }

    in.seekg(0, std::ios::beg);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    if (!nlohmann::json::accept(content)) {
        IAM_LOGE("invalid JSON format.");
        return false;
    }
    jsonBuf = nlohmann::json::parse(content);
    if (jsonBuf.is_discarded()) {
        IAM_LOGE("bad profile file");
        return false;
    }

    return true;
}

bool GetStringArrayFromJson(const nlohmann::json &jsonObject,
    std::vector<std::string> &exemptedBundleInfos,
    const std::string &key)
{
    if (jsonObject.is_null()) {
        IAM_LOGE("jsonObject is null");
        return false;
    }
    if (jsonObject.is_array() && !jsonObject.is_discarded()) {
        for (const auto &object : jsonObject) {
            if (!object.is_object()) {
                IAM_LOGE("is not object");
                return false;
            }
            const auto &objectEnd = object.end();
            if (object.find(key) != objectEnd && object[key].is_array()) {
                exemptedBundleInfos = object.at(key).get<std::vector<std::string>>();
                break;
            }
        }
        return true;
    }
    IAM_LOGE("getStringArrayFromJson error");
    return false;
}

bool GetStringFromJson(const nlohmann::json &jsonObject, std::string &exemptedBundleInfo,
    const std::string &key)
{
    if (jsonObject.is_null()) {
        IAM_LOGE("jsonObject is null");
        return false;
    }
    if (jsonObject.is_array() && !jsonObject.is_discarded()) {
        for (const auto &object : jsonObject) {
            if (!object.is_object()) {
                IAM_LOGE("is not object");
                return false;
            }
            const auto &objectEnd = object.end();
            if (object.find(key) != objectEnd && object[key].is_string()) {
                exemptedBundleInfo = object.at(key).get<std::string>();
                return true;
            }
        }
    }
    IAM_LOGE("getStringFromJson error");
    return false;
}
}

// utils
AuthType Str2AuthType(const std::string &strAuthType)
{
    AuthType authType = AuthType::ALL;
    if (strAuthType.compare(AUTH_TYPE_ALL) == 0) {
        authType = AuthType::ALL;
    } else if (strAuthType.compare(AUTH_TYPE_PIN) == 0) {
        authType = AuthType::PIN;
    } else if (strAuthType.compare(AUTH_TYPE_FACE) == 0) {
        authType = AuthType::FACE;
    } else if (strAuthType.compare(AUTH_TYPE_FINGER_PRINT) == 0) {
        authType = AuthType::FINGERPRINT;
    } else if (strAuthType.compare(AUTH_TYPE_PRIVATE_PIN) == 0) {
        authType = AuthType::PRIVATE_PIN;
    } else if (strAuthType.compare(AUTH_TYPE_COMPANION_DEVICE) == 0) {
        authType = AuthType::COMPANION_DEVICE;
    } else {
        IAM_LOGE("strAuthType: %{public}s", strAuthType.c_str());
    }
    return authType;
}

std::string AuthType2Str(const AuthType &authType)
{
    std::string strAuthType = "";
    switch (authType) {
        case AuthType::ALL: {
            strAuthType = AUTH_TYPE_ALL;
            break;
        }
        case AuthType::PIN: {
            strAuthType = AUTH_TYPE_PIN;
            break;
        }
        case AuthType::FACE: {
            strAuthType = AUTH_TYPE_FACE;
            break;
        }
        case AuthType::FINGERPRINT: {
            strAuthType = AUTH_TYPE_FINGER_PRINT;
            break;
        }
        case AuthType::PRIVATE_PIN: {
            strAuthType = AUTH_TYPE_PRIVATE_PIN;
            break;
        }
        case AuthType::COMPANION_DEVICE: {
            strAuthType = AUTH_TYPE_COMPANION_DEVICE;
            break;
        }
        default: {
            IAM_LOGE("authType: %{public}u", authType);
        }
    }
    return strAuthType;
}

std::string WinModeType2Str(const WindowModeType &winModeType)
{
    std::string strWinModeType = "";
    switch (winModeType) {
        case WindowModeType::DIALOG_BOX: {
            strWinModeType = WINDOW_MODE_DIALOG;
            break;
        }
        case WindowModeType::FULLSCREEN: {
            strWinModeType = WINDOW_MODE_FULLSCREEN;
            break;
        }
        case WindowModeType::NONE_INTERRUPTION_DIALOG_BOX: {
            strWinModeType = WINDOW_MODE_NONE_INTERRUPTION_DIALOG_BOX;
            break;
        }
        default: {
            IAM_LOGE("winModeType: %{public}u", winModeType);
        }
    }
    return strWinModeType;
}

std::vector<AuthType> WidgetNotice::AuthTypeList() const
{
    std::vector<AuthType> authTypeList;
    for (const auto &type : typeList) {
        authTypeList.emplace_back(Str2AuthType(type));
    }
    return authTypeList;
}

std::string PinSubType2Str(const PinSubType &subType)
{
    std::string strPinSubType = "";
    switch (subType) {
        case PinSubType::PIN_SIX: {
            strPinSubType = PIN_SUB_TYPE_SIX;
            break;
        }
        case PinSubType::PIN_NUMBER: {
            strPinSubType = PIN_SUB_TYPE_NUM;
            break;
        }
        case PinSubType::PIN_MIXED: {
            strPinSubType = PIN_SUB_TYPE_MIX;
            break;
        }
        case PinSubType::PIN_FOUR: {
            strPinSubType = PIN_SUB_TYPE_FOUR;
            break;
        }
        case PinSubType::PIN_PATTERN: {
            strPinSubType = PIN_SUB_TYPE_PATTERN;
            break;
        }
        case PinSubType::PIN_MAX: {
            strPinSubType = PIN_SUB_TYPE_MAX;
            break;
        }
        default: {
            IAM_LOGE("subType: %{public}u", subType);
        }
    }
    return strPinSubType;
}

void to_json(nlohmann::json &jsonNotice, const WidgetNotice &notice)
{
    auto type = nlohmann::json({{JSON_AUTH_TYPE, notice.typeList},
        {JSON_AUTH_END_AFTER_FIRST_FAIL, notice.endAfterFirstFail},
        {JSON_AUTH_INTENT, notice.authIntent},
        {JSON_AUTH_TIP_CODE, notice.tipCode}});
    jsonNotice = nlohmann::json({{JSON_WIDGET_CTX_ID, notice.widgetContextId},
        {JSON_AUTH_EVENT, notice.event},
        {JSON_ORIENTATION, notice.orientation},
        {JSON_NEED_ROTATE, notice.needRotate},
        {JSON_ALREADY_LOAD, notice.alreadyLoad},
        {JSON_AUTH_VERSION, notice.version},
        {JSON_AUTH_PAYLOAD, type}});
}

bool isNumberItem(const nlohmann::json &jsonNotice, const std::string &item)
{
    if (jsonNotice.find(item) != jsonNotice.end() && jsonNotice[item].is_number()) {
        return true;
    }
    return false;
}

void from_json(const nlohmann::json &jsonNotice, WidgetNotice &notice)
{
    if (isNumberItem(jsonNotice, JSON_WIDGET_CTX_ID)) {
        jsonNotice.at(JSON_WIDGET_CTX_ID).get_to(notice.widgetContextId);
    }
    if (jsonNotice.find(JSON_AUTH_EVENT) != jsonNotice.end() && jsonNotice[JSON_AUTH_EVENT].is_string()) {
        jsonNotice.at(JSON_AUTH_EVENT).get_to(notice.event);
    }
    if (isNumberItem(jsonNotice, JSON_ORIENTATION)) {
        jsonNotice.at(JSON_ORIENTATION).get_to(notice.orientation);
    }
    if (isNumberItem(jsonNotice, JSON_NEED_ROTATE)) {
        jsonNotice.at(JSON_NEED_ROTATE).get_to(notice.needRotate);
    }
    if (isNumberItem(jsonNotice, JSON_ALREADY_LOAD)) {
        jsonNotice.at(JSON_ALREADY_LOAD).get_to(notice.alreadyLoad);
    }
    if (jsonNotice.find(JSON_AUTH_VERSION) != jsonNotice.end() && jsonNotice[JSON_AUTH_VERSION].is_string()) {
        jsonNotice.at(JSON_AUTH_VERSION).get_to(notice.version);
    }
    if (jsonNotice.find(JSON_AUTH_PAYLOAD) == jsonNotice.end()) {
        return;
    }
    if (jsonNotice[JSON_AUTH_PAYLOAD].find(JSON_AUTH_TYPE) != jsonNotice[JSON_AUTH_PAYLOAD].end() &&
        jsonNotice[JSON_AUTH_PAYLOAD][JSON_AUTH_TYPE].is_array()) {
        for (size_t index = 0; index < jsonNotice[JSON_AUTH_PAYLOAD][JSON_AUTH_TYPE].size(); index++) {
            if (!jsonNotice[JSON_AUTH_PAYLOAD][JSON_AUTH_TYPE].at(index).is_string()) {
                notice.typeList.clear();
                break;
            }
            notice.typeList.emplace_back(jsonNotice[JSON_AUTH_PAYLOAD][JSON_AUTH_TYPE].at(index).get<std::string>());
        }
    }
    if ((jsonNotice[JSON_AUTH_PAYLOAD].find(JSON_AUTH_END_AFTER_FIRST_FAIL) !=
            jsonNotice[JSON_AUTH_PAYLOAD].end()) &&
        jsonNotice[JSON_AUTH_PAYLOAD][JSON_AUTH_END_AFTER_FIRST_FAIL].is_boolean()) {
        jsonNotice[JSON_AUTH_PAYLOAD].at(JSON_AUTH_END_AFTER_FIRST_FAIL).get_to(notice.endAfterFirstFail);
    }
    if (isNumberItem(jsonNotice[JSON_AUTH_PAYLOAD], JSON_AUTH_INTENT)) {
        jsonNotice[JSON_AUTH_PAYLOAD].at(JSON_AUTH_INTENT).get_to(notice.authIntent);
    }
    if (isNumberItem(jsonNotice[JSON_AUTH_PAYLOAD], JSON_AUTH_TIP_CODE)) {
        jsonNotice[JSON_AUTH_PAYLOAD].at(JSON_AUTH_TIP_CODE).get_to(notice.tipCode);
    }
}

std::string GetConfigRealPath()
{
    char buf[MAX_PATH_LEN] = { 0 };
    char *configPath = GetOneCfgFile(AUTH_WIDGE_CONFIG_SUFFIX, buf, MAX_PATH_LEN);
    if (configPath == nullptr || configPath[0] == '\0' || strlen(configPath) > MAX_PATH_LEN) {
        IAM_LOGE("get configPath error");
        return AUTH_WIDGE_CONFIG_SUFFIX;
    }
    return std::string(configPath);
}

void LoadConfigJsonBuffer(nlohmann::json &jsonBuf)
{
    IAM_LOGI("LoadConfig start");
    std::string configPath = GetConfigRealPath();
    if (!ReadFileIntoJson(configPath, jsonBuf)) {
        IAM_LOGE("ReadFileIntoJson failed");
    }
}

bool GetSceneboardBundleName(nlohmann::json &jsonBuf, std::string &processName)
{
    IAM_LOGI("enter");
    if (!GetStringFromJson(jsonBuf, processName, SCENEBOARD_BUNDLE_NAME)) {
        IAM_LOGE("GetStringFromJson failed");
        return false;
    }
    return true;
}

bool GetSceneboardAbilityName(nlohmann::json &jsonBuf, std::string &processName)
{
    IAM_LOGI("enter");
    if (!GetStringFromJson(jsonBuf, processName, SCENEBOARD_ABILITY_NAME)) {
        IAM_LOGE("GetStringFromJson failed");
        return false;
    }
    return true;
}

bool GetProcessName(nlohmann::json &jsonBuf, std::vector<std::string> &processName)
{
    IAM_LOGI("enter");
    if (!GetStringArrayFromJson(jsonBuf, processName, SHWO_WITH_LEVEL_2_WINDOW)) {
        IAM_LOGE("GetStringArrayFromJson failed");
        return false;
    }
    return true;
}

bool GetFollowCallerList(nlohmann::json &jsonBuf, std::vector<std::string> &processName)
{
    IAM_LOGI("enter");
    if (!GetStringArrayFromJson(jsonBuf, processName, FOLLOW_CALLER_WINDOW_WHEN_FOLDED)) {
        IAM_LOGE("GetStringArrayFromJson failed");
        return false;
    }
    return true;
}

bool GetAlwaysSupportFollowCallerUi(nlohmann::json &jsonBuf, std::vector<std::string> &processName)
{
    IAM_LOGI("enter");
    if (!GetStringArrayFromJson(jsonBuf, processName, ALWAYS_SUPPORT_FOLLOW_CALLER_UI)) {
        IAM_LOGE("GetStringArrayFromJson failed");
        return false;
    }
    return true;
}

void to_json(nlohmann::json &jsonCommand, const WidgetCommand &command)
{
    GetJsonCmd(jsonCommand, command);
}

// WidgetCmdParameters
void to_json(nlohmann::json &jsWidgetCmdParam, const WidgetCmdParameters &widgetCmdParameters)
{
    nlohmann::json jsonCommand;
    GetJsonCmd(jsonCommand, widgetCmdParameters.useriamCmdData);

    jsWidgetCmdParam = nlohmann::json({{JSON_UI_EXTENSION_TYPE, widgetCmdParameters.uiExtensionType},
        {JSON_SYS_DIALOG_ZORDER, widgetCmdParameters.sysDialogZOrder},
        {JSON_UI_EXT_NODE_ANGLE, widgetCmdParameters.uiExtNodeAngle},
        {JSON_FOCUS_STATE, widgetCmdParameters.focusState},
        {JSON_IS_ENABLE_ROTATE, DISABLE_ROTATE},
        {JSON_USER_IAM_CMD_DATA, jsonCommand}
    });
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
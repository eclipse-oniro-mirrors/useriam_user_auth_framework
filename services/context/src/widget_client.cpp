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

#include "widget_client.h"

#include "system_ability_definition.h"

#include "auth_common.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_time.h"
#include "nlohmann/json.hpp"
#include "iwidget_callback.h"
#include "hisysevent_adapter.h"

#define LOG_FILE_ID LOG_FILE_WIDGET_CLIENT
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

const std::string PIN_SUB_TYPE_SIX = "PIN_SIX";
const std::string PIN_SUB_TYPE_NUMBER = "PIN_NUMBER";
const std::string PIN_SUB_TYPE_MIXED = "PIN_MIXED";
const std::string PIN_SUB_TYPE_FOUR = "PIN_FOUR";
const std::string PIN_SUB_TYPE_PATTERN = "PIN_PATTERN";
const std::string PIN_SUB_TYPE_MAX = "PIN_MAX";

WidgetClient &WidgetClient::Instance()
{
    static WidgetClient widgetClient;
    return widgetClient;
}

WidgetClient::~WidgetClient()
{
    IAM_LOGD("start.");
    ForceStopAuth();
}

void WidgetClient::SetWidgetSchedule(uint64_t contextId, const std::shared_ptr<WidgetScheduleNode> &schedule)
{
    IF_FALSE_LOGE_AND_RETURN(schedule != nullptr);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    widgetContextId_ = contextId;
    schedule_ = schedule;
    InsertScheduleNode(widgetContextId_, schedule_);
}

ResultCode WidgetClient::OnNotice(NoticeType type, const std::string &eventData)
{
    // handle notice from widget
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (type != WIDGET_NOTICE) {
        IAM_LOGE("Invalid notice type");
        return ResultCode::INVALID_PARAMETERS;
    }
    if (eventData.empty()) {
        IAM_LOGE("Invalid notice event data");
        return ResultCode::INVALID_PARAMETERS;
    }
    IAM_LOGI("recv notice eventData: %{public}s", eventData.c_str());
    auto root = nlohmann::json::parse(eventData.c_str(), nullptr, false);
    if (root.is_null() || root.is_discarded()) {
        IAM_LOGE("OnNotice eventData is not json format");
        return ResultCode::INVALID_PARAMETERS;
    }
    if (!root.is_object()) {
        IAM_LOGE("type check failed.");
        return ResultCode::INVALID_PARAMETERS;
    }
    WidgetNotice notice = root.get<WidgetNotice>();
    if (notice.widgetContextId == 0) {
        IAM_LOGE("Invalid widget context id");
        return ResultCode::INVALID_PARAMETERS;
    }
    if (!IsValidNoticeType(notice)) {
        IAM_LOGE("Not support notice event");
        return ResultCode::INVALID_PARAMETERS;
    }
    if (schedule_ == nullptr) {
        IAM_LOGE("Invalid schedule node, report auth false");
        return ResultCode::GENERAL_ERROR;
    }
    std::vector<AuthType> authTypeList = {};
    if (!GetAuthTypeList(notice, authTypeList)) {
        IAM_LOGE("Invalid auth type list");
        return ResultCode::INVALID_PARAMETERS;
    }
    ProcessNotice(notice, authTypeList);
    return ResultCode::SUCCESS;
}

void WidgetClient::ProcessNotice(const WidgetNotice &notice, std::vector<AuthType> &authTypeList)
{
    HILOG_COMM_INFO("widget client, event:%{public}s, authTypeSize: %{public}zu",
        notice.event.c_str(), authTypeList.size());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (notice.event == NOTICE_EVENT_AUTH_READY) {
        schedule_->StartAuthList(authTypeList, notice.endAfterFirstFail, notice.authIntent);
    } else if (notice.event == NOTICE_EVENT_CANCEL_AUTH) {
        if (notice.widgetContextId != widgetContextId_) {
            IAM_LOGE("Invalid widgetContextId ****%{public}hx", static_cast<uint16_t>(widgetContextId_));
            return;
        }
        if (authTypeList.size() == 1 && authTypeList[0] == AuthType::ALL) {
            schedule_->StopSchedule();
        } else {
            schedule_->StopAuthList(authTypeList);
        }
    } else if (notice.event == NOTICE_EVENT_USER_NAVIGATION) {
        schedule_->NaviPinAuth();
    } else if (notice.event == NOTICE_EVENT_WIDGET_PARA_INVALID) {
        schedule_->WidgetParaInvalid();
    } else if (notice.event == NOTICE_EVENT_END) {
        schedule_->StopAuthList(authTypeList);
    } else if (notice.event == NOTICE_EVENT_RELOAD) {
        if ((authTypeList.size() == 1 && authTypeList[0] == AuthType::ALL) || authTypeList.size() != 1) {
            schedule_->WidgetParaInvalid();
        } else {
            schedule_->WidgetReload(notice.orientation, notice.needRotate, notice.alreadyLoad, authTypeList[0]);
        }
    } else if (notice.event == NOTICE_EVENT_AUTH_WIDGET_LOADED) {
        WidgetLoad(notice.widgetContextId, authTypeList);
    } else if (notice.event == NOTICE_EVENT_AUTH_WIDGET_RELEASED) {
        WidgetRelease(notice.widgetContextId, authTypeList);
    } else if (notice.event == NOTICE_EVENT_PROCESS_TERMINATE) {
        ClearSchedule(notice.widgetContextId);
    } else if (notice.event == NOTICE_EVENT_AUTH_SEND_TIP) {
        schedule_->SendAuthTipInfo(authTypeList, notice.tipCode);
    }
}

void WidgetClient::SendCommand(const WidgetCommand &command)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (widgetCallback_ == nullptr) {
        IAM_LOGE("SendCommand widget callback is null");
        return;
    }
    nlohmann::json root = command;
    std::string cmdData;
    try {
        cmdData = root.dump();
    } catch (const nlohmann::json::exception &e) {
        IAM_LOGE("cmd is invalid json, error: %{public}s", e.what());
        return;
    }
    IAM_LOGD("SendCommand cmdData");
    widgetCallback_->SendCommand(cmdData);
}

void WidgetClient::ReportWidgetResult(int32_t result, AuthType authType,
    int32_t lockoutDuration, int32_t remainAttempts, bool skipLockedBiometricAuth)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    WidgetCommand::ExtraInfo extraInfo {
        .callingBundleName = callingBundleName_,
        .challenge = challenge_
    };
    // sendCommand of CMD_NOTIFY_AUTH_RESULT
    WidgetCommand::Cmd cmd {
        .event = CMD_NOTIFY_AUTH_RESULT,
        .version = NOTICE_VERSION_STR,
        .type = AuthType2Str(authType),
        .result = result,
        .lockoutDuration = lockoutDuration,
        .remainAttempts = remainAttempts,
        .extraInfo = extraInfo
    };
    if (authType == AuthType::FINGERPRINT && !sensorInfo_.empty()) {
        cmd.sensorInfo = sensorInfo_;
    }
    WidgetCommand widgetCmd {
        .widgetContextId = widgetContextId_,
        .title = widgetParam_.title,
        .windowModeType = WinModeType2Str(widgetParam_.windowMode),
        .navigationButtonText = widgetParam_.navigationButtonText,
        .cmdList = { cmd },
        .skipLockedBiometricAuth = skipLockedBiometricAuth
    };
    for (auto &type : authTypeList_) {
        widgetCmd.typeList.emplace_back(AuthType2Str(type));
    }
    if (!pinSubType_.empty()) {
        widgetCmd.pinSubType = pinSubType_;
    }
    SendCommand(widgetCmd);
}

void WidgetClient::ReportWidgetTip(int32_t tipType, AuthType authType, std::vector<uint8_t> tipInfo,
    bool skipLockedBiometricAuth)
{
    // sendCommand of CMD_NOTIFY_AUTH_TIP
    WidgetCommand::Cmd cmd {
        .event = CMD_NOTIFY_AUTH_TIP,
        .version = NOTICE_VERSION_STR,
        .type = AuthType2Str(authType),
        .tipType = tipType,
        .tipInfo = tipInfo
    };
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    WidgetCommand widgetCmd {
        .widgetContextId = widgetContextId_,
        .cmdList = { cmd },
        .skipLockedBiometricAuth = skipLockedBiometricAuth
    };
    SendCommand(widgetCmd);
}

void WidgetClient::SetWidgetParam(const WidgetParamInner &param)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    widgetParam_ = param;
}

void WidgetClient::SetAuthTypeList(const std::vector<AuthType> &authTypeList)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    authTypeList_ = authTypeList;
}

void WidgetClient::SetWidgetCallback(const sptr<IWidgetCallback> &callback)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    widgetCallback_ = callback;
}

void WidgetClient::SetAuthTokenId(uint32_t tokenId)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    authTokenId_ = tokenId;
    IAM_LOGI("WidgetClient SetAuthTokenId authTokenId: %{public}s", GET_MASKED_STRING(authTokenId_).c_str());
}

uint32_t WidgetClient::GetAuthTokenId()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return authTokenId_;
}

void WidgetClient::Reset()
{
    IAM_LOGI("WidgetClient Reset");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    widgetParam_.title.clear();
    widgetParam_.navigationButtonText.clear();
    widgetParam_.windowMode = WindowModeType::DIALOG_BOX;
    widgetContextId_ = 0;
    authTokenId_ = 0;
    schedule_ = nullptr;
    widgetCallback_ = nullptr;
    pinSubType_.clear();
    sensorInfo_.clear();
}

void WidgetClient::ForceStopAuth()
{
    IAM_LOGI("stop auth process forcely by disconnect");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (schedule_ != nullptr) {
        schedule_->StopSchedule();
    }
    ClearSchedule(widgetContextId_);
}

void WidgetClient::SetPinSubType(const PinSubType &subType)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    pinSubType_ = PIN_SUB_TYPE_SIX;
    switch (subType) {
        case PinSubType::PIN_NUMBER:
            pinSubType_ = PIN_SUB_TYPE_NUMBER;
            break;
        case PinSubType::PIN_MIXED:
            pinSubType_ = PIN_SUB_TYPE_MIXED;
            break;
        case PinSubType::PIN_MAX:
            pinSubType_ = PIN_SUB_TYPE_MAX;
            break;
        case PinSubType::PIN_FOUR:
            pinSubType_ = PIN_SUB_TYPE_FOUR;
            break;
        case PinSubType::PIN_PATTERN:
            pinSubType_ = PIN_SUB_TYPE_PATTERN;
            break;
        default:
            break;
    }
}

void WidgetClient::SetSensorInfo(const std::string &info)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    sensorInfo_ = info;
}

bool WidgetClient::GetAuthTypeList(const WidgetNotice &notice, std::vector<AuthType> &authTypeList)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (authTypeList_.empty()) {
        IAM_LOGE("inner auth type list is empty");
        return false;
    }
    std::vector<AuthType> tempList = notice.AuthTypeList();
    if (tempList.empty()) {
        IAM_LOGE("auth type list is empty");
        return false;
    }
    if (tempList.size() == 1 && tempList[0] == AuthType::ALL) {
        if (notice.event != NOTICE_EVENT_CANCEL_AUTH && notice.event != NOTICE_EVENT_PROCESS_TERMINATE) {
            IAM_LOGE("invalid type all case event type: %{public}s", notice.event.c_str());
            return false;
        }
        authTypeList.emplace_back(AuthType::ALL);
        return true;
    }
    for (auto &type : tempList) {
        authTypeList.emplace_back(type);
    }
    if (authTypeList.size() == authTypeList_.size() && notice.event == NOTICE_EVENT_CANCEL_AUTH) {
        authTypeList.clear();
        authTypeList.emplace_back(AuthType::ALL);
    }
    return true;
}

bool WidgetClient::IsValidNoticeType(const WidgetNotice &notice)
{
    if (notice.event != NOTICE_EVENT_AUTH_READY &&
        notice.event != NOTICE_EVENT_CANCEL_AUTH &&
        notice.event != NOTICE_EVENT_USER_NAVIGATION &&
        notice.event != NOTICE_EVENT_WIDGET_PARA_INVALID &&
        notice.event != NOTICE_EVENT_RELOAD &&
        notice.event != NOTICE_EVENT_END &&
        notice.event != NOTICE_EVENT_AUTH_WIDGET_LOADED &&
        notice.event != NOTICE_EVENT_AUTH_WIDGET_RELEASED &&
        notice.event != NOTICE_EVENT_PROCESS_TERMINATE &&
        notice.event != NOTICE_EVENT_AUTH_SEND_TIP) {
        return false;
    }
    return true;
}

void WidgetClient::SetChallenge(const std::vector<uint8_t> &challenge)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    challenge_ = challenge;
}

void WidgetClient::SetCallingBundleName(const std::string &callingBundleName)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    callingBundleName_ = callingBundleName;
}

void WidgetClient::InsertScheduleNode(uint64_t contextId, std::shared_ptr<WidgetScheduleNode> &scheduleNode)
{
    IAM_LOGI("start, contextId:%{public}hx", static_cast<uint16_t>(contextId));
    IF_FALSE_LOGE_AND_RETURN(scheduleNode != nullptr);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    scheduleMap_.insert(std::pair<uint64_t, std::shared_ptr<WidgetScheduleNode>>(contextId, scheduleNode));
}

void WidgetClient::RemoveScheduleNode(uint64_t contextId)
{
    IAM_LOGI("start, contextId:%{public}hx", static_cast<uint16_t>(contextId));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    scheduleMap_.erase(contextId);
}

std::shared_ptr<WidgetScheduleNode> WidgetClient::GetScheduleNode(uint64_t contextId)
{
    IAM_LOGI("start, contextId:%{public}hx", static_cast<uint16_t>(contextId));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::shared_ptr<WidgetScheduleNode> scheduleNode = nullptr;
    auto iter = scheduleMap_.find(contextId);
    if (iter != scheduleMap_.end()) {
        scheduleNode = iter->second;
        IAM_LOGI("success, contextId:%{public}hx", static_cast<uint16_t>(contextId));
    }
    return scheduleNode;
}

void WidgetClient::ClearSchedule(uint64_t contextId)
{
    IAM_LOGI("start, contextId:%{public}hx", static_cast<uint16_t>(contextId));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto schedule = GetScheduleNode(contextId);
    if (schedule != nullptr) {
        if (contextId == widgetContextId_) {
            Reset();
            if (!loadedAuthTypeList_.empty()) {
                schedule->SendAuthTipInfo(loadedAuthTypeList_, TIP_CODE_WIDGET_RELEASED);
                loadedAuthTypeList_.clear();
            }
        }
        schedule->StopSchedule();
        schedule->ClearSchedule();
        RemoveScheduleNode(contextId);
    }
}

void WidgetClient::WidgetLoad(uint64_t contextId, std::vector<AuthType> &authTypeList)
{
    IAM_LOGI("start, contextId:%{public}hx", static_cast<uint16_t>(contextId));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto schedule = GetScheduleNode(contextId);
    if (schedule != nullptr) {
        if (contextId != widgetContextId_) {
            IAM_LOGE("widgetContextId_:%{public}hx", static_cast<uint16_t>(widgetContextId_));
            return;
        }
        schedule->SendAuthTipInfo(authTypeList, TIP_CODE_WIDGET_LOADED);
        loadedAuthTypeList_ = authTypeList;
    }
}

void WidgetClient::WidgetRelease(uint64_t contextId, std::vector<AuthType> &authTypeList)
{
    IAM_LOGI("start, contextId:%{public}hx", static_cast<uint16_t>(contextId));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto schedule = GetScheduleNode(contextId);
    if (schedule != nullptr) {
        schedule->SendAuthTipInfo(authTypeList, TIP_CODE_WIDGET_RELEASED);
        if (contextId != widgetContextId_) {
            IAM_LOGI("widgetContextId_:%{public}hx", static_cast<uint16_t>(widgetContextId_));
            return;
        }
        loadedAuthTypeList_.clear();
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

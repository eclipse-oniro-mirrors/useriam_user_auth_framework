/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hisysevent_adapter.h"

#include <cinttypes>

#include "hisysevent.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_time.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;

constexpr char STR_USER_ID[] = "USER_ID";
constexpr char STR_AUTH_TYPE[] = "AUTH_TYPE";
constexpr char STR_OPERATION_TYPE[] = "OPERATION_TYPE";
constexpr char STR_OPERATION_RESULT[] = "OPERATION_RESULT";
constexpr char STR_AUTH_RESULT[] = "AUTH_RESULT";
constexpr char STR_TRIGGER_REASON[] = "TRIGGER_REASON";
constexpr char STR_CHANGE_TYPE[] = "CHANGE_TYPE";
constexpr char STR_EXECUTOR_TYPE[] = "EXECUTOR_TYPE";
constexpr char STR_MODULE_NAME[] = "MODULE_NAME";
constexpr char STR_HAPPEN_TIME[] = "HAPPEN_TIME";
constexpr char STR_AUTH_TRUST_LEVEL[] = "AUTH_TRUST_LEVEL";
constexpr char STR_SDK_VERSION[] = "SDK_VERSION";
constexpr char STR_AUTH_WIDGET_TYPE[] = "AUTH_WIDGET_TYPE";
constexpr char STR_CALLER_NAME[] = "CALLER_NAME";
constexpr char STR_REQUEST_CONTEXTID[] = "REQUEST_CONTEXTID";
constexpr char STR_TIME_SPAN[] = "TIME_SPAN";
constexpr char STR_AUTH_TIME_SPAN[] = "AUTH_TIME_SPAN";
constexpr char STR_AUTH_CONTEXTID[] = "AUTH_CONTEXTID";
constexpr char STR_SCHEDULE_ID[] = "SCHEDULE_ID";
constexpr char STR_REUSE_UNLOCK_RESULT_TYPE[] = "REUSE_UNLOCK_RESULT_TYPE";
constexpr char STR_REUSE_UNLOCK_RESULT_DURATION[] = "REUSE_UNLOCK_RESULT_DURATION";
constexpr char STR_IS_REMOTE_AUTH[] = "IS_REMOTE_AUTH";
constexpr char STR_LOCAL_UDID[] = "LOCAL_UDID";
constexpr char STR_REMOTE_UDID[] = "REMOTE_UDID";
constexpr char STR_CONNECTION_NAME[] = "CONNECTION_NAME";
constexpr char STR_NETWORK_ID[] = "NETWORK_ID";
constexpr char STR_SOCKET_ID[] = "SOCKET_ID";
constexpr char STR_AUTH_FINISH_REASON[] = "AUTH_FINISH_REASON";
constexpr char STR_OPERATION_TIME[] = "OPERATION_TIME";

static std::string MaskForStringId(const std::string &id)
{
    const int32_t MASK_WIDTH = 64;
    if (id.length() != MASK_WIDTH) {
        return "****";
    }
    return id.substr(0, MASK_WIDTH) + "**" + id.substr(id.length() - MASK_WIDTH, id.length());
}

void ReportSystemFault(const std::string &timeString, const std::string &moudleName)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_SYSTEM_FAULT",
        HiSysEvent::EventType::FAULT,
        STR_HAPPEN_TIME, timeString,
        STR_MODULE_NAME, moudleName);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, timeString %{public}s, moudleName %{public}s.",
            ret, timeString.c_str(), moudleName.c_str());
    }
}

void ReportSecurityTemplateChange(const TemplateChangeTrace &info)
{
    std::string operationTime = Common::GetNowTimeString();
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_TEMPLATE_CHANGE",
        HiSysEvent::EventType::SECURITY,
        STR_OPERATION_TIME, operationTime,
        STR_SCHEDULE_ID, info.scheduleId,
        STR_EXECUTOR_TYPE, info.executorType,
        STR_CHANGE_TYPE, info.changeType,
        STR_TRIGGER_REASON, info.reason);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void ReportBehaviorCredManager(const UserCredManagerTrace &info)
{
    std::string operationTime = Common::GetNowTimeString();
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_USER_CREDENTIAL_MANAGER",
        HiSysEvent::EventType::BEHAVIOR,
        STR_OPERATION_TIME, operationTime,
        STR_CALLER_NAME, info.callerName,
        STR_USER_ID, info.userId,
        STR_AUTH_TYPE, info.authType,
        STR_OPERATION_TYPE, info.operationType,
        STR_OPERATION_RESULT, info.operationResult);
    if (ret != 0) {
            IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void ReportSecurityCredChange(const UserCredChangeTrace &info)
{
    std::string operationTime = Common::GetNowTimeString();
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_CREDENTIAL_CHANGE",
        HiSysEvent::EventType::SECURITY,
        STR_OPERATION_TIME, operationTime,
        STR_CALLER_NAME, info.callerName,
        STR_REQUEST_CONTEXTID, info.requestContextId,
        STR_USER_ID, info.userId,
        STR_AUTH_TYPE, info.authType,
        STR_OPERATION_TYPE, info.operationType,
        STR_OPERATION_RESULT, info.operationResult,
        STR_TIME_SPAN, info.timeSpan);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void ReportUserAuth(const UserAuthTrace &info)
{
    std::string operationTime = Common::GetNowTimeString();
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_USER_AUTH",
        HiSysEvent::EventType::BEHAVIOR,
        STR_OPERATION_TIME, operationTime,
        STR_CALLER_NAME, info.callerName,
        STR_SDK_VERSION, info.sdkVersion,
        STR_AUTH_TRUST_LEVEL, info.atl,
        STR_AUTH_TYPE, info.authType,
        STR_AUTH_RESULT, info.authResult,
        STR_AUTH_TIME_SPAN, info.authtimeSpan,
        STR_AUTH_WIDGET_TYPE, info.authWidgetType,
        STR_REUSE_UNLOCK_RESULT_TYPE, info.reuseUnlockResultMode,
        STR_REUSE_UNLOCK_RESULT_DURATION, info.reuseUnlockResultDuration,
        STR_IS_REMOTE_AUTH, info.isRemoteAuth,
        STR_LOCAL_UDID, MaskForStringId(info.localUdid),
        STR_REMOTE_UDID, MaskForStringId(info.remoteUdid),
        STR_CONNECTION_NAME, info.connectionName,
        STR_AUTH_FINISH_REASON, info.authFinishReason);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void ReportSecurityUserAuthFwk(const UserAuthFwkTrace &info)
{
    std::string operationTime = Common::GetNowTimeString();
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_USER_AUTH_FWK",
        HiSysEvent::EventType::SECURITY,
        STR_OPERATION_TIME, operationTime,
        STR_CALLER_NAME, info.callerName,
        STR_REQUEST_CONTEXTID, info.requestContextId,
        STR_AUTH_CONTEXTID, info.authContextId,
        STR_AUTH_TRUST_LEVEL, info.atl,
        STR_AUTH_TYPE, info.authType,
        STR_AUTH_RESULT, info.authResult,
        STR_AUTH_TIME_SPAN, info.authtimeSpan,
        STR_IS_REMOTE_AUTH, info.isRemoteAuth,
        STR_LOCAL_UDID, MaskForStringId(info.localUdid),
        STR_REMOTE_UDID, MaskForStringId(info.remoteUdid),
        STR_CONNECTION_NAME, info.connectionName,
        STR_AUTH_FINISH_REASON, info.authFinishReason);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void ReportRemoteExecuteProc(const RemoteExecuteTrace &info)
{
    std::string operationTime = Common::GetNowTimeString();
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_REMOTE_EXECUTE",
        HiSysEvent::EventType::BEHAVIOR,
        STR_OPERATION_TIME, operationTime,
        STR_SCHEDULE_ID, info.scheduleId,
        STR_CONNECTION_NAME, info.connectionName,
        STR_OPERATION_RESULT, info.operationResult);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void ReportRemoteConnectOpen(const RemoteConnectOpenTrace &info)
{
    std::string operationTime = Common::GetNowTimeString();
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_REMOTE_CONNECT",
        HiSysEvent::EventType::BEHAVIOR,
        STR_OPERATION_TIME, operationTime,
        STR_CONNECTION_NAME, info.connectionName,
        STR_OPERATION_RESULT, info.operationResult,
        STR_TIME_SPAN, info.timeSpan,
        STR_NETWORK_ID, MaskForStringId(info.networkId),
        STR_SOCKET_ID, info.socketId);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void ReportConnectFaultTrace(const RemoteConnectFaultTrace &info)
{
    std::ostringstream ss;
    ss << "reason: " << info.reason << ", socketId: " << info.socketId << ", connectionName: " << info.connectionName
        << ", msgType:" << info.msgType << ", messageSeq" << "ack:" << info.ack;
    ReportSystemFault(Common::GetNowTimeString(), ss.str());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
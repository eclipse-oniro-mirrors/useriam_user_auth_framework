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

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;

constexpr char STR_USER_ID[] = "USER_ID";
constexpr char STR_CALLING_ID[] = "CALLING_ID";
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
constexpr char STR_AUTH_TIME_SPAN[] = "AUTH_TIME_SPAN";
constexpr char STR_SDK_VERSION[] = "SDK_VERSION";
constexpr char STR_AUTH_WIDGET_TYPE[] = "AUTH_WIDGET_TYPE";
constexpr char STR_BUNDLE_NAME[] = "BUNDLE_NAME";
constexpr char STR_CONTEXT_ID[] = "CONTEXT_ID";
constexpr char STR_CONSUMING_TIME[] = "CONSUMING_TIME";

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

void ReportTemplateChange(int32_t executorType, uint32_t changeType, const std::string &reason)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_TEMPLATE_CHANGE",
        HiSysEvent::EventType::SECURITY,
        STR_EXECUTOR_TYPE, executorType,
        STR_CHANGE_TYPE, changeType,
        STR_TRIGGER_REASON, reason);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, executorType %{public}d,"
            "changeType %{public}u, trigger reason %{public}s.",
            ret, executorType, changeType, reason.c_str());
    }
}
void ReportBehaviorCredChange(int32_t userId, int32_t authType, uint32_t operationType, uint32_t optResult,
    std::string bundleName)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_USER_CREDENTIAL_MANAGER",
        HiSysEvent::EventType::BEHAVIOR,
        STR_USER_ID, userId,
        STR_AUTH_TYPE, authType,
        STR_OPERATION_TYPE, operationType,
        STR_OPERATION_RESULT, optResult,
        STR_BUNDLE_NAME, bundleName);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, userId %{public}d, authType %{public}d,"
            "operationType %{public}u, optResult %{public}u, bundleName %{public}s.",
            ret, userId, authType, operationType, optResult, bundleName.c_str());
    }
}

void ReportSecurityCredChange(int32_t userId, int32_t authType, uint32_t operationType, uint32_t optResult,
    std::string bundleName, uint64_t contextId, uint64_t consumingTime)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_CREDENTIAL_CHANGE",
        HiSysEvent::EventType::SECURITY,
        STR_USER_ID, userId,
        STR_AUTH_TYPE, authType,
        STR_OPERATION_TYPE, operationType,
        STR_OPERATION_RESULT, optResult,
        STR_BUNDLE_NAME, bundleName,
        STR_CONTEXT_ID, contextId,
        STR_CONSUMING_TIME, consumingTime);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, userId %{public}d, authType %{public}d,"
            "operationType %{public}u, optResult %{public}u, bundleName %{public}s, contextId %{public}u,"
            "consumingTime %{public}u.",
            ret, userId, authType, operationType, optResult, bundleName, contextId, consumingTime);
    }
}

void ReportUserAuth(const UserAuthInfo &info)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_USER_AUTH",
        HiSysEvent::EventType::BEHAVIOR,
        STR_CALLING_ID, info.callingUid,
        STR_AUTH_TYPE, info.authType,
        STR_AUTH_TRUST_LEVEL, info.atl,
        STR_AUTH_RESULT, info.authResult,
        STR_AUTH_TIME_SPAN, info.timeSpanString,
        STR_SDK_VERSION, info.sdkVersion,
        STR_AUTH_WIDGET_TYPE, info.authWidgetType,
        STR_BUNDLE_NAME, info.bundleName);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, callingUid %{public}"  PRIu64 ", authType %{public}d,"
            "atl %{public}u, authResult %{public}u, timeSpanString %{public}s,"
            "sdkVersion%{public}u, authwidgetType%{public}u, bundleName %{public}s",
            ret, info.callingUid, info.authType, info.atl, info.authResult,
            info.timeSpanString.c_str(), info.sdkVersion, info.authWidgetType, info.bundleName.c_str());
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
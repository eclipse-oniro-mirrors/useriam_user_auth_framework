/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "trace.h"

#include <cinttypes>
#include <sstream>
#include "iam_logger.h"
#include "iam_time.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_TRACE

using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
Trace Trace::trace;

Trace::Trace()
{
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessCredChangeEvent);
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessCredManagerEvent);
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessUserAuthEvent);
}

Trace::~Trace()
{
}

void Trace::ProcessCredChangeEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    if (!(metaData.operationType == TRACE_ADD_CREDENTIAL ||
        metaData.operationType == TRACE_DELETE_CREDENTIAL ||
        metaData.operationType == TRACE_UPDATE_CREDENTIAL ||
        metaData.operationType == TRACE_DELETE_USER ||
        metaData.operationType == TRACE_ENFORCE_DELETE_USER ||
        metaData.operationType == TRACE_DELETE_REDUNDANCY)) {
        return;
    }
    UserCredChangeTrace securityInfo = {};
    if (metaData.callerName.has_value()) {
        securityInfo.callerName = metaData.callerName.value();
    }
    if (metaData.requestContextId.has_value()) {
        securityInfo.requestContextId = metaData.requestContextId.value();
    }
    if (metaData.userId.has_value()) {
        securityInfo.userId = metaData.userId.value();
    }
    if (metaData.authType.has_value()) {
        securityInfo.authType = metaData.authType.value();
    }
    securityInfo.operationType = metaData.operationType;
    securityInfo.operationResult = metaData.operationResult;
    uint64_t timeSpan = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(metaData.endTime -
        metaData.startTime).count());
    securityInfo.timeSpan = timeSpan;
    ReportSecurityCredChange(securityInfo);
    IAM_LOGI("start to process cred change event");
}

void Trace::ProcessCredManagerEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    if (!(metaData.operationType == TRACE_ADD_CREDENTIAL ||
        metaData.operationType == TRACE_DELETE_CREDENTIAL ||
        metaData.operationType == TRACE_UPDATE_CREDENTIAL ||
        metaData.operationType == TRACE_DELETE_USER ||
        metaData.operationType == TRACE_ENFORCE_DELETE_USER)) {
        return;
    }
    UserCredManagerTrace info = {};
    if (metaData.callerName.has_value()) {
        info.callerName = metaData.callerName.value();
    }
    if (metaData.userId.has_value()) {
        info.userId = metaData.userId.value();
    }
    if (metaData.authType.has_value()) {
        info.authType = metaData.authType.value();
    }
    info.operationType = metaData.operationType;
    info.operationResult = metaData.operationResult;
    ReportBehaviorCredManager(info);
    IAM_LOGI("start to process cred manager event");
}

template<typename T, typename U>
void CopyOptionalValue(const std::optional<T> &src, U &dst)
{
    if (src.has_value()) {
        dst = static_cast<U>(src.value());
    }
}

template<typename T>
void CopyOptionalValue(const std::optional<T> &src, T &dst)
{
    if (src.has_value()) {
        dst = src.value();
    }
}

void Trace::CopyMetaDataToTraceInfo(const ContextCallbackNotifyListener::MetaData &metaData, UserAuthTrace &info)
{
    CopyOptionalValue(metaData.callerName, info.callerName);
    CopyOptionalValue(metaData.sdkVersion, info.sdkVersion);
    CopyOptionalValue(metaData.atl, info.atl);
    if (metaData.operationResult == SUCCESS) {
        CopyOptionalValue(metaData.authType, info.authType);
    }
    CopyOptionalValue(metaData.userId, info.userId);
    CopyOptionalValue(metaData.callerType, info.callerType);
    info.authResult = metaData.operationResult;
    info.authtimeSpan = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        metaData.endTime - metaData.startTime).count());
    CopyOptionalValue(metaData.authWidgetType, info.authWidgetType);
    CopyOptionalValue(metaData.reuseUnlockResultMode, info.reuseUnlockResultMode);
    CopyOptionalValue(metaData.reuseUnlockResultDuration, info.reuseUnlockResultDuration);
    CopyOptionalValue(metaData.isRemoteAuth, info.isRemoteAuth);
    CopyOptionalValue(metaData.remoteUdid, info.remoteUdid);
    CopyOptionalValue(metaData.localUdid, info.localUdid);
    CopyOptionalValue(metaData.connectionName, info.connectionName);
    CopyOptionalValue(metaData.authFinishReason, info.authFinishReason);
    CopyOptionalValue(metaData.isBackgroundApplication, info.isBackgroundApplication);
    CopyOptionalValue(metaData.totalTime, info.timeTraceInfo.totalTime);
    CopyOptionalValue(metaData.localTime, info.timeTraceInfo.localTime);
    CopyOptionalValue(metaData.authSuccTipTime, info.timeTraceInfo.authSuccTipTime);
    CopyOptionalValue(metaData.extraInfo, info.timeTraceInfo.extraInfo);
    CopyOptionalValue(metaData.requestContextId, info.requestContextId);
    CopyOptionalValue(metaData.authContextId, info.authContextId);
}

void Trace::ProcessUserAuthEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    if (!(metaData.operationType == TRACE_AUTH_USER_BEHAVIOR ||
        metaData.operationType == TRACE_AUTH_USER_SECURITY)) {
        return;
    }
    UserAuthTrace info = {};
    CopyMetaDataToTraceInfo(metaData, info);
    ReportUserAuth(info);
    IAM_LOGD("start to process user auth event");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
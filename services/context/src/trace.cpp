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
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessUserAuthFwkEvent);
}

Trace::~Trace()
{
}

void Trace::ProcessCredChangeEvent(const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag)
{
    static_cast<void>(flag);
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

void Trace::ProcessCredManagerEvent(const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag)
{
    static_cast<void>(flag);
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
}

void Trace::ProcessUserAuthEvent(const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag)
{
    if (!(metaData.operationType == TRACE_AUTH_USER_ALL ||
        metaData.operationType == TRACE_AUTH_USER_BEHAVIOR) ||
        (flag == TRACE_FLAG_NO_NEED_BEHAVIOR)) {
        return;
    }
    UserAuthTrace info = {};
    CopyMetaDataToTraceInfo(metaData, info);
    ReportUserAuth(info);
    IAM_LOGD("start to process user auth event");
}

void Trace::ProcessUserAuthFwkEvent(const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag)
{
    static_cast<void>(flag);
    if (!(metaData.operationType == TRACE_AUTH_USER_ALL ||
        metaData.operationType == TRACE_AUTH_USER_SECURITY)) {
        return;
    }
    UserAuthFwkTrace securityInfo = {};
    if (metaData.callerName.has_value()) {
        securityInfo.callerName = metaData.callerName.value();
    }
    if (metaData.requestContextId.has_value()) {
        securityInfo.requestContextId = metaData.requestContextId.value();
    }
    if (metaData.authContextId.has_value()) {
        securityInfo.authContextId = metaData.authContextId.value();
    }
    if (metaData.atl.has_value()) {
        securityInfo.atl = metaData.atl.value();
    }
    if (metaData.authType.has_value()) {
        securityInfo.authType = metaData.authType.value();
    }
    if (metaData.isRemoteAuth.has_value()) {
        securityInfo.isRemoteAuth = metaData.isRemoteAuth.value();
    }
    if (metaData.remoteUdid.has_value()) {
        securityInfo.remoteUdid = metaData.remoteUdid.value();
    }
    if (metaData.localUdid.has_value()) {
        securityInfo.localUdid = metaData.localUdid.value();
    }
    if (metaData.connectionName.has_value()) {
        securityInfo.connectionName = metaData.connectionName.value();
    }
    if (metaData.authFinishReason.has_value()) {
        securityInfo.authFinishReason = metaData.authFinishReason.value();
    }
    CopyOptionalValue(metaData.totalTime, securityInfo.timeTraceInfo.totalTime);
    CopyOptionalValue(metaData.localTime, securityInfo.timeTraceInfo.localTime);
    CopyOptionalValue(metaData.authSuccTipTime, securityInfo.timeTraceInfo.authSuccTipTime);
    CopyOptionalValue(metaData.extraInfo, securityInfo.timeTraceInfo.extraInfo);
    securityInfo.authResult = metaData.operationResult;
    uint64_t timeSpan = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(metaData.endTime -
        metaData.startTime).count());
    securityInfo.authtimeSpan = timeSpan;
    ReportSecurityUserAuthFwk(securityInfo);
    IAM_LOGD("start to process user auth fwk event");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
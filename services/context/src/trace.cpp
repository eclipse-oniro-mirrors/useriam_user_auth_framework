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
#include "hisysevent_adapter.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

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
    uint64_t timeSpan = std::chrono::duration_cast<std::chrono::milliseconds>(metaData.endTime -
        metaData.startTime).count();
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

void Trace::ProcessUserAuthEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    if (!(metaData.operationType == TRACE_AUTH_USER_ALL ||
        metaData.operationType == TRACE_AUTH_USER_BEHAVIOR)) {
        return;
    }
    UserAuthTrace info = {};
    if (metaData.callerName.has_value()) {
        info.callerName = metaData.callerName.value();
    }
    if (metaData.sdkVersion.has_value()) {
        info.sdkVersion = metaData.sdkVersion.value();
    }
    if (metaData.atl.has_value()) {
        info.atl = metaData.atl.value();
    }
    if (metaData.authType.has_value() && metaData.operationResult == SUCCESS) {
        info.authType = metaData.authType.value();
    }
    info.authResult = metaData.operationResult;
    uint64_t timeSpan = std::chrono::duration_cast<std::chrono::milliseconds>(metaData.endTime -
        metaData.startTime).count();
    info.timeSpan = timeSpan;
    if (metaData.authWidgetType.has_value()) {
        info.authWidgetType = metaData.authWidgetType.value();
    }
    ReportUserAuth(info);
    IAM_LOGI("start to process user auth event");
}

void Trace::ProcessUserAuthFwkEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
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
    securityInfo.authResult = metaData.operationResult;
    uint64_t timeSpan = std::chrono::duration_cast<std::chrono::milliseconds>(metaData.endTime -
        metaData.startTime).count();
    securityInfo.timeSpan = timeSpan;
    ReportSecurityUserAuthFwk(securityInfo);
    IAM_LOGI("start to process user auth fwk event");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
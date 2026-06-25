/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef IAM_CONTEXT_FACTORY_H
#define IAM_CONTEXT_FACTORY_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "singleton.h"
#include "authentication_impl.h"
#include "delete_impl.h"
#include "enrollment_impl.h"
#include "context.h"
#include "context_callback.h"
#include "local_remote_auth_context.h"
#include "identification_impl.h"
#include "imodal_callback.h"
#include "iremote_auth_callback.h"
#include "remote_auth_context.h"
#include "remote_auth_invoker_context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ContextFactory : public DelayedSingleton<ContextFactory> {
public:
    struct AuthProfile {
        int32_t pinSubType {0};
        std::string sensorInfo {""};
        int32_t remainTimes {0};
        int32_t freezingTime {0};
        uint32_t cameraStatus {0};
    };

    struct AuthWidgetContextPara {
        int32_t userId {INVALID_USER_ID};
        int32_t sdkVersion {0};
        uint32_t tokenId {0};
        std::string callerName {""};
        std::vector<uint8_t> challenge {};
        std::vector<AuthType> authTypeList {};
        AuthTrustLevel atl {ATL1};
        WidgetParamInner widgetParam {};
        std::map<AuthType, AuthProfile> authProfileMap {};
        int32_t callerType {0};
        std::string callingAppID {""};
        bool isPinExpired {false};
        bool isOsAccountVerified {false};
        bool isBackgroundApplication {false};
        bool skipLockedBiometricAuth {false};
        std::vector<uint64_t> credentialIdList {};
        std::string remoteCallerName {""};
    };

    static std::shared_ptr<Context> CreateSimpleAuthContext(const Authentication::AuthenticationPara &para,
        const std::shared_ptr<ContextCallback> &callback, bool needSubscribeAppState);
    static std::shared_ptr<Context> CreateRemoteAuthContext(const Authentication::AuthenticationPara &para,
        RemoteAuthContextParam &remoteAuthContextParam, const std::shared_ptr<ContextCallback> &callback);
    static std::shared_ptr<Context> CreateRemoteAuthInvokerContext(AuthParamInner authParam,
        RemoteAuthInvokerContextParam param, std::shared_ptr<ContextCallback> callback);
    static std::shared_ptr<Context> CreateLocalRemoteAuthContext(const Authentication::AuthenticationPara &para,
        LocalRemoteAuthContextParam &localRemoteAuthContextParam, const std::shared_ptr<ContextCallback> &callback);
    static std::shared_ptr<Context> CreateIdentifyContext(const Identification::IdentificationPara &para,
        const std::shared_ptr<ContextCallback> &callback);
    static std::shared_ptr<Context> CreateEnrollContext(const Enrollment::EnrollmentPara &para,
        const std::shared_ptr<ContextCallback> &callback, bool needSubscribeAppState);
    static std::shared_ptr<Context> CreateWidgetAuthContext(std::shared_ptr<ContextCallback> callback);
    static std::shared_ptr<Context> CreateWidgetContext(const AuthWidgetContextPara &para,
        std::shared_ptr<ContextCallback> callback, const sptr<IModalCallback> &modalCallback,
        const sptr<IRemoteAuthCallback> &remoteAuthCallback);
    static std::shared_ptr<Context> CreateScheduleHolderContext(std::shared_ptr<ScheduleNode> scheduleNode);
    static std::shared_ptr<Context> CreateDeleteContext(const Deletion::DeleteParam &para,
        const std::shared_ptr<ContextCallback> &callback);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_FACTORY_H
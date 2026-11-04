/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef IAM_MOCK_USER_AUTH_ENGINE_H
#define IAM_MOCK_USER_AUTH_ENGINE_H

#include <memory>
#include <mutex>

#include <gmock/gmock.h>

#include "singleton.h"

#include "user_auth_engine.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
// Test-only aliases: business UT keeps its existing Hdi* spelling, but the fake
// now sits at the IUserAuthEngine abstraction, so no HDI headers are needed.
using HdiExecutorRegisterInfo = CoAuthInterface::ExecutorRegisterInfo;
using HdiEnrollResultInfo = EngEnrollResultInfo;
using HdiCredentialOperateResult = EngCredentialOperateResult;
using HdiCredentialInfo = EngCredentialInfo;
using HdiEnrolledInfo = EnrolledInfo;
using HdiScheduleInfo = EngScheduleInfo;
using HdiIdentifyResultInfo = EngIdentifyResultInfo;
using HdiEnrollParamExt = EngEnrollParamExt;
using HdiAuthParamExt = EngAuthParamExt;
using HdiAuthResultInfo = EngAuthResultInfo;
using HdiEnrolledState = EngEnrolledState;
using HdiReuseUnlockInfo = EngReuseUnlockInfo;
using HdiReuseUnlockParam = EngReuseUnlockParam;
using HdiGlobalConfigParam = EngGlobalConfigParam;
using HdiGlobalConfigValue = EngGlobalConfigValue;
using HdiUserAuthTokenPlain = EngUserAuthTokenPlain;
using HdiExtUserInfo = EngExtUserInfo;
using HdiUserInfo = EngUserInfo;
using HdiExecutorSendMsg = EngExecutorSendMsg;
using HdiCredentialOperateType = EngCredentialOperateType;
using HdiAuthType = AuthType;
using HdiScheduleMode = ScheduleMode;
using HdiIMessageCallback = IMessageCallback;

class MockUserAuthEngine final : public IUserAuthEngine {
public:
    class Holder;
    MOCK_METHOD1(Init, int32_t(const std::string &deviceUdid));
    MOCK_METHOD4(AddExecutor, int32_t(const CoAuthInterface::ExecutorRegisterInfo &info, uint64_t &index,
                                  std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds));
    MOCK_METHOD1(DeleteExecutor, int32_t(uint64_t index));
    MOCK_METHOD2(OpenSession, int32_t(int32_t userId, std::vector<uint8_t> &challenge));
    MOCK_METHOD1(CloseSession, int32_t(int32_t userId));
    MOCK_METHOD3(BeginEnrollment,
        int32_t(const std::vector<uint8_t> &authToken, const EngEnrollParam &param, EngScheduleInfo &info));
    MOCK_METHOD3(UpdateEnrollmentResult, int32_t(int32_t userId, const std::vector<uint8_t> &scheduleResult,
                                             EngEnrollResultInfo &info));
    MOCK_METHOD1(CancelEnrollment, int32_t(int32_t userId));
    MOCK_METHOD3(BeginAuthentication,
        int32_t(uint64_t contextId, const EngAuthParam &param, std::vector<EngScheduleInfo> &scheduleInfos));
    MOCK_METHOD4(BeginAuthenticationExt, int32_t(uint64_t contextId, EngAuthParamExt &param,
        std::vector<EngScheduleInfo> &scheduleInfos, AcquireInfoCallback &acquireInfoCallback));
    MOCK_METHOD5(UpdateAuthenticationResult, int32_t(uint64_t contextId,
        const std::vector<uint8_t> &scheduleResult, EngAuthResultInfo &info, EngEnrolledState &enrolledState,
        AcquireInfoCallback &acquireInfoCallback));
    MOCK_METHOD1(CancelAuthentication, int32_t(uint64_t contextId));
    MOCK_METHOD3(GetCredential, int32_t(int32_t userId, int32_t authType, std::vector<EngCredentialInfo> &infos));
    MOCK_METHOD4(DeleteCredential, int32_t(int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t> &authToken, EngCredentialOperateResult &operateResult));
    MOCK_METHOD4(GetAvailableStatus, int32_t(int32_t userId, int32_t authType, uint32_t authTrustLevel,
        int32_t &checkResult));
    MOCK_METHOD4(GetUserInfo,
        int32_t(int32_t userId, uint64_t &secureUid, int32_t &pinSubType, std::vector<EnrolledInfo> &infos));
    MOCK_METHOD4(DeleteUser,
        int32_t(int32_t userId, const std::vector<uint8_t> &authToken, std::vector<EngCredentialInfo> &deletedInfos,
            std::vector<uint8_t> &rootSecret));
    MOCK_METHOD2(EnforceDeleteUser, int32_t(int32_t userId, std::vector<EngCredentialInfo> &deletedInfos));
    MOCK_METHOD1(GetAllExtUserInfo, int32_t(std::vector<EngExtUserInfo> &userInfos));
    MOCK_METHOD2(GetCredentialById, int32_t(uint64_t credentialId, EngCredentialInfo &info));
    MOCK_METHOD2(ClearUnavailableCredential, int32_t(const std::vector<int32_t> &userIds,
        std::vector<EngCredentialInfo> &infos));
    MOCK_METHOD3(DeleteSubProfile,
        int32_t(int32_t userId, int32_t subProfileId, std::vector<EngCredentialInfo> &deletedInfos));
    MOCK_METHOD3(UpdateAbandonResult, int32_t(int32_t userId, const std::vector<uint8_t> &scheduleResult,
        std::vector<EngCredentialInfo> &infos));
    MOCK_METHOD5(BeginIdentification,
        int32_t(uint64_t contextId, int32_t authType, const std::vector<uint8_t> &challenge, uint32_t executorSensorHint,
            EngScheduleInfo &scheduleInfo));
    MOCK_METHOD3(UpdateIdentificationResult,
        int32_t(uint64_t contextId, const std::vector<uint8_t> &scheduleResult, EngIdentifyResultInfo &info));
    MOCK_METHOD1(CancelIdentification, int32_t(uint64_t contextId));
    MOCK_METHOD3(BeginEnrollmentExt,
        int32_t(const std::vector<uint8_t> &authToken, const EngEnrollParamExt &param, EngScheduleInfo &info));
    MOCK_METHOD3(SendMessage, int32_t(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg));
    MOCK_METHOD4(GetSignedExecutorInfo, int32_t(const std::vector<int32_t> &authTypes, int32_t executorRole,
        const std::string &remoteUdid, std::vector<uint8_t> &signedExecutorInfo));
    MOCK_METHOD1(PrepareRemoteAuth, int32_t(const std::string &remoteUdid));
    MOCK_METHOD3(GetEnrolledState, int32_t(int32_t userId, int32_t authType, EngEnrolledState &enrolledState));
    MOCK_METHOD1(SetGlobalConfigParam, int32_t(const EngGlobalConfigParam &param));
    MOCK_METHOD1(SetUserConfigParam, int32_t(const EngGlobalConfigParam &param));
    MOCK_METHOD4(GetUserConfigParam,
        int32_t(int32_t userId, int32_t authType, int32_t type, EngGlobalConfigValue &value));
    MOCK_METHOD4(VerifyAuthToken, int32_t(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        EngUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t> &rootSecret));
    MOCK_METHOD1(RegisterMessageCallback, int32_t(const sptr<IMessageCallback> &messageCallback));
    MOCK_METHOD4(GetValidSolution, int32_t(int32_t userId, const std::vector<int32_t> &authTypes,
        uint32_t authTrustLevel, std::vector<int32_t> &validTypes));
    MOCK_METHOD2(CheckReuseUnlockResult, int32_t(const EngReuseUnlockParam &reuseParam, EngReuseUnlockInfo &reuseInfo));
    MOCK_METHOD3(GetLocalScheduleFromMessage, int32_t(const std::string &remoteUdid,
        const std::vector<uint8_t> &message, EngScheduleInfo &scheduleInfo));
    MOCK_METHOD3(GetAuthResultFromMessage, int32_t(
        const std::string &remoteUdid, const std::vector<uint8_t> &message, EngAuthResultInfo &authResultInfo));
    MOCK_METHOD3(GetLatestEnrollmentTime, int32_t(int32_t userId, int32_t authType, uint64_t &latestEnrollmentTime));
    MOCK_METHOD1(SetStatusCallback, bool(const StateCallback &callback));
    MOCK_METHOD0(Load, int32_t());
    MOCK_METHOD0(Unload, int32_t());
    MOCK_CONST_METHOD1(IsWidgetCallerAllowedOnLockScreen, bool(const EngCallerAuthInfo &callerInfo));
};

class MockUserAuthEngine::Holder : public Singleton<MockUserAuthEngine::Holder> {
public:
    void Reset();
    std::shared_ptr<MockUserAuthEngine> Get();

private:
    std::mutex mutex_;
    std::shared_ptr<MockUserAuthEngine> mock_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_AUTH_ENGINE_H

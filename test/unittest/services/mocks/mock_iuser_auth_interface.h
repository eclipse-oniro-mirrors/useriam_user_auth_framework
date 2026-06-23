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
#ifndef IAM_MOCK_IUSER_AUTH_INTERFACE_H
#define IAM_MOCK_IUSER_AUTH_INTERFACE_H

#include <memory>
#include <mutex>

#include <gmock/gmock.h>

#include "singleton.h"

#include "hdi_wrapper.h"
#include "user_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockIUserAuthInterface final : public IUserAuthInterface {
public:
    class Holder;
    MOCK_METHOD1(Init, int32_t(const std::string &deviceUdid));

    MOCK_METHOD4(AddExecutor, int32_t(const HdiExecutorRegisterInfo &info, uint64_t &index,
                                  std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds));
    MOCK_METHOD1(DeleteExecutor, int32_t(uint64_t index));
    MOCK_METHOD2(OpenSession, int32_t(int32_t userId, std::vector<uint8_t> &challenge));
    MOCK_METHOD1(CloseSession, int32_t(int32_t userId));
    MOCK_METHOD3(UpdateEnrollmentResult, int32_t(int32_t userId, const std::vector<uint8_t> &scheduleResult,
                                             HdiEnrollResultInfo &info));
    MOCK_METHOD1(CancelEnrollment, int32_t(int32_t userId));
    MOCK_METHOD4(DeleteCredential, int32_t(int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t> &authToken, HdiCredentialOperateResult &operateResult));
    MOCK_METHOD3(GetCredential, int32_t(int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos));
    MOCK_METHOD4(GetUserInfo,
        int32_t(int32_t userId, uint64_t &secureUid, int32_t &pinSubType, std::vector<HdiEnrolledInfo> &infos));
    MOCK_METHOD4(DeleteUser,
        int32_t(int32_t userId, const std::vector<uint8_t> &authToken, std::vector<HdiCredentialInfo> &deletedInfos,
            std::vector<uint8_t> &rootSecret));
    MOCK_METHOD2(EnforceDeleteUser, int32_t(int32_t userId, std::vector<HdiCredentialInfo> &deletedInfos));
    MOCK_METHOD1(CancelAuthentication, int32_t(uint64_t contextId));
    MOCK_METHOD3(UpdateIdentificationResult,
        int32_t(uint64_t contextId, const std::vector<uint8_t> &scheduleResult, HdiIdentifyResultInfo &info));
    MOCK_METHOD1(CancelIdentification, int32_t(uint64_t contextId));
    MOCK_METHOD4(GetAvailableStatus, int32_t(int32_t userId, int32_t authType, uint32_t authTrustLevel,
        int32_t &checkRet));
    MOCK_METHOD4(GetValidSolution, int32_t(int32_t userId, const std::vector<int32_t> &authTypes,
        uint32_t authTrustLevel, std::vector<int32_t> &validTypes));
    MOCK_METHOD5(BeginIdentification,
        int32_t(uint64_t contextId, int32_t authType, const std::vector<uint8_t> &challenge, uint32_t executorId,
            HdiScheduleInfo &scheduleInfo));
    MOCK_METHOD1(GetAllUserInfo, int32_t(std::vector<UserInfo> &userInfos));
    MOCK_METHOD1(GetAllExtUserInfo, int32_t(std::vector<ExtUserInfo> &userInfos));
    MOCK_METHOD3(BeginEnrollment,
        int32_t(const std::vector<uint8_t> &authToken, const HdiEnrollParam &param, HdiScheduleInfo &info));
    MOCK_METHOD3(BeginEnrollmentExt,
        int32_t(const std::vector<uint8_t> &authToken, const HdiEnrollParamExt &param, HdiScheduleInfo &info));
    MOCK_METHOD3(BeginAuthentication,
        int32_t(uint64_t contextId, const HdiAuthParam &param, std::vector<HdiScheduleInfo> &scheduleInfos));
    MOCK_METHOD3(BeginAuthenticationExt,
        int32_t(uint64_t contextId, const HdiAuthParamExt &param, std::vector<HdiScheduleInfo> &scheduleInfos));
    MOCK_METHOD3(GetEnrolledState, int32_t(int32_t userId, int32_t authType, HdiEnrolledState &hdiEnrolledState));
    MOCK_METHOD4(UpdateAuthenticationResult, int32_t(uint64_t contextId,
        const std::vector<uint8_t> &scheduleResult, HdiAuthResultInfo &info, HdiEnrolledState &enrolledState));
    MOCK_METHOD2(CheckReuseUnlockResult, int32_t(const HdiReuseUnlockParam &reuseParam, HdiReuseUnlockInfo &reuseInfo));
    MOCK_METHOD3(SendMessage, int32_t(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg));
    MOCK_METHOD1(RegisterMessageCallback, int32_t(const sptr<HdiIMessageCallback> &messageCallback));
    MOCK_METHOD1(PrepareRemoteAuth, int32_t(const std::string &remoteUdid));
    MOCK_METHOD3(GetLocalScheduleFromMessage, int32_t(const std::string &remoteUdid,
        const std::vector<uint8_t> &message, HdiScheduleInfo &scheduleInfo));
    MOCK_METHOD4(GetSignedExecutorInfo, int32_t(const std::vector<int32_t> &authTypes, int32_t executorRole,
        const std::string &remoteUdid, std::vector<uint8_t> &signedExecutorInfo));
    MOCK_METHOD1(SetGlobalConfigParam, int32_t(const HdiGlobalConfigParam &param));
    MOCK_METHOD3(GetAuthResultFromMessage, int32_t(
        const std::string &remoteUdid, const std::vector<uint8_t> &message, HdiAuthResultInfo &authResultInfo));
    MOCK_METHOD4(VerifyAuthToken, int32_t(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        HdiUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t> &rootSecret));
    MOCK_METHOD2(GetCredentialById, int32_t(uint64_t credentialId, HdiCredentialInfo &info));
    MOCK_METHOD3(UpdateAbandonResult, int32_t(int32_t userId, const std::vector<uint8_t> &scheduleResult,
        std::vector<HdiCredentialInfo> &infos));
    MOCK_METHOD2(ClearUnavailableCredential, int32_t(const std::vector<int32_t> &userIds,
        std::vector<HdiCredentialInfo> &infos));
};

class MockIUserAuthInterface::Holder : public Singleton<MockIUserAuthInterface::Holder> {
public:
    void Reset();
    std::shared_ptr<MockIUserAuthInterface> Get();

private:
    std::mutex mutex_;
    std::shared_ptr<MockIUserAuthInterface> mock_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_IUSER_AUTH_INTERFACE_H
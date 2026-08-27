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

#define LOG_FILE_ID LOG_FILE_HDI_ENGINE

#include "hdi_engine_fuzzer.h"
#include "hdi_engine.h"

#include <cstdint>
#include <string>
#include <vector>

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "parcel.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

// ---- helpers: fill Eng types from Parcel -----------------------------------

void FillFuzzInt32Vector(Parcel &parcel, std::vector<int32_t> &data)
{
    uint32_t len = parcel.ReadUint32() % 10;
    data.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        data[i] = parcel.ReadInt32();
    }
}

void FillEngExecutorRegisterInfo(Parcel &parcel, CoAuthInterface::ExecutorRegisterInfo &info)
{
    info.authType = static_cast<AuthType>(parcel.ReadInt32());
    info.executorRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    info.executorSensorHint = parcel.ReadUint32();
    info.executorMatcher = parcel.ReadUint32();
    info.esl = static_cast<ExecutorSecureLevel>(parcel.ReadInt32());
    info.maxTemplateAcl = parcel.ReadUint32();
    Common::FillFuzzUint8Vector(parcel, info.publicKey);
    Common::FillFuzzString(parcel, info.deviceUdid);
    Common::FillFuzzUint8Vector(parcel, info.signedRemoteExecutorInfo);
}

void FillEngEnrollParam(Parcel &parcel, EngEnrollParam &param)
{
    param.authType = parcel.ReadInt32();
    param.executorSensorHint = parcel.ReadUint32();
    Common::FillFuzzString(parcel, param.callerName);
    param.callerType = parcel.ReadInt32();
    param.apiVersion = parcel.ReadInt32();
    param.userId = parcel.ReadInt32();
    param.userType = parcel.ReadInt32();
    param.authSubType = parcel.ReadInt32();
}

void FillEngEnrollParamExt(Parcel &parcel, EngEnrollParamExt &param)
{
    param.authType = parcel.ReadInt32();
    param.executorSensorHint = parcel.ReadUint32();
    Common::FillFuzzString(parcel, param.callerName);
    param.callerType = parcel.ReadInt32();
    param.apiVersion = parcel.ReadInt32();
    param.userId = parcel.ReadInt32();
    param.userType = parcel.ReadInt32();
    param.authSubType = parcel.ReadInt32();
    Common::FillFuzzString(parcel, param.additionalInfo);
}

void FillEngAuthParamBase(Parcel &parcel, EngAuthParamBase &base)
{
    base.userId = parcel.ReadInt32();
    base.authTrustLevel = parcel.ReadUint32();
    base.executorSensorHint = parcel.ReadUint32();
    Common::FillFuzzUint8Vector(parcel, base.challenge);
    Common::FillFuzzString(parcel, base.callerName);
    base.callerType = parcel.ReadInt32();
    base.apiVersion = parcel.ReadInt32();
}

void FillEngAuthParam(Parcel &parcel, EngAuthParam &param)
{
    FillEngAuthParamBase(parcel, param.baseParam);
    param.authType = parcel.ReadInt32();
    param.authIntent = parcel.ReadInt32();
    param.isOsAccountVerified = parcel.ReadBool();
    Common::FillFuzzString(parcel, param.collectorUdid);
}

void FillEngAuthParamExt(Parcel &parcel, EngAuthParamExt &param)
{
    FillEngAuthParamBase(parcel, param.baseParam);
    param.authType = parcel.ReadInt32();
    param.authIntent = parcel.ReadInt32();
    param.isOsAccountVerified = parcel.ReadBool();
    Common::FillFuzzString(parcel, param.collectorUdid);
    Common::FillFuzzUint64Vector(parcel, param.credentialIdList);
}

void FillEngReuseUnlockParam(Parcel &parcel, EngReuseUnlockParam &param)
{
    FillEngAuthParamBase(parcel, param.baseParam);
    FillFuzzInt32Vector(parcel, param.authTypes);
    param.reuseUnlockResultDuration = parcel.ReadUint64();
    param.reuseUnlockResultMode = parcel.ReadInt32();
}

void FillEngGlobalConfigParam(Parcel &parcel, EngGlobalConfigParam &param)
{
    param.type = parcel.ReadInt32();
    param.value.pinExpiredPeriod = parcel.ReadInt64();
    FillFuzzInt32Vector(parcel, param.userIds);
    FillFuzzInt32Vector(parcel, param.authTypes);
}

// ---- individual fuzz functions ---------------------------------------------

void FuzzInit(Parcel &parcel)
{
    IAM_LOGI("start");
    std::string deviceUdid;
    Common::FillFuzzString(parcel, deviceUdid);
    (void)GetUserAuthEngine().Init(deviceUdid);
    IAM_LOGI("end");
}

void FuzzAddExecutor(Parcel &parcel)
{
    IAM_LOGI("start");
    CoAuthInterface::ExecutorRegisterInfo info;
    FillEngExecutorRegisterInfo(parcel, info);
    uint64_t index = 0;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;
    (void)GetUserAuthEngine().AddExecutor(info, index, publicKey, templateIds);
    IAM_LOGI("end");
}

void FuzzDeleteExecutor(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t index = parcel.ReadUint64();
    (void)GetUserAuthEngine().DeleteExecutor(index);
    IAM_LOGI("end");
}

void FuzzOpenSession(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    (void)GetUserAuthEngine().OpenSession(userId, challenge);
    IAM_LOGI("end");
}

void FuzzCloseSession(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    (void)GetUserAuthEngine().CloseSession(userId);
    IAM_LOGI("end");
}

void FuzzBeginEnrollment(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> authToken;
    Common::FillFuzzUint8Vector(parcel, authToken);
    EngEnrollParam param;
    FillEngEnrollParam(parcel, param);
    EngScheduleInfo info;
    (void)GetUserAuthEngine().BeginEnrollment(authToken, param, info);
    IAM_LOGI("end");
}

void FuzzUpdateEnrollmentResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> scheduleResult;
    Common::FillFuzzUint8Vector(parcel, scheduleResult);
    EngEnrollResultInfo info;
    (void)GetUserAuthEngine().UpdateEnrollmentResult(userId, scheduleResult, info);
    IAM_LOGI("end");
}

void FuzzCancelEnrollment(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    (void)GetUserAuthEngine().CancelEnrollment(userId);
    IAM_LOGI("end");
}

void FuzzBeginAuthentication(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    EngAuthParam param;
    FillEngAuthParam(parcel, param);
    std::vector<EngScheduleInfo> scheduleInfos;
    (void)GetUserAuthEngine().BeginAuthentication(contextId, param, scheduleInfos);
    IAM_LOGI("end");
}

void FuzzUpdateAuthenticationResult(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    std::vector<uint8_t> scheduleResult;
    Common::FillFuzzUint8Vector(parcel, scheduleResult);
    EngAuthResultInfo info;
    EngEnrolledState enrolledState;
    (void)GetUserAuthEngine().UpdateAuthenticationResult(contextId, scheduleResult, info, enrolledState);
    IAM_LOGI("end");
}

void FuzzCancelAuthentication(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    (void)GetUserAuthEngine().CancelAuthentication(contextId);
    IAM_LOGI("end");
}

void FuzzGetCredential(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    int32_t authType = parcel.ReadInt32();
    std::vector<EngCredentialInfo> infos;
    (void)GetUserAuthEngine().GetCredential(userId, authType, infos);
    IAM_LOGI("end");
}

void FuzzDeleteCredential(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    uint64_t credentialId = parcel.ReadUint64();
    std::vector<uint8_t> authToken;
    Common::FillFuzzUint8Vector(parcel, authToken);
    EngCredentialOperateResult operateResult;
    (void)GetUserAuthEngine().DeleteCredential(userId, credentialId, authToken, operateResult);
    IAM_LOGI("end");
}

void FuzzGetAvailableStatus(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    int32_t authType = parcel.ReadInt32();
    uint32_t authTrustLevel = parcel.ReadUint32();
    int32_t checkResult = 0;
    (void)GetUserAuthEngine().GetAvailableStatus(userId, authType, authTrustLevel, checkResult);
    IAM_LOGI("end");
}

void FuzzGetUserInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    uint64_t secureUid = 0;
    int32_t pinSubType = 0;
    std::vector<EnrolledInfo> infos;
    (void)GetUserAuthEngine().GetUserInfo(userId, secureUid, pinSubType, infos);
    IAM_LOGI("end");
}

void FuzzDeleteUser(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> authToken;
    Common::FillFuzzUint8Vector(parcel, authToken);
    std::vector<EngCredentialInfo> deletedInfos;
    std::vector<uint8_t> rootSecret;
    (void)GetUserAuthEngine().DeleteUser(userId, authToken, deletedInfos, rootSecret);
    IAM_LOGI("end");
}

void FuzzEnforceDeleteUser(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    std::vector<EngCredentialInfo> deletedInfos;
    (void)GetUserAuthEngine().EnforceDeleteUser(userId, deletedInfos);
    IAM_LOGI("end");
}

void FuzzGetAllExtUserInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<EngExtUserInfo> userInfos;
    (void)GetUserAuthEngine().GetAllExtUserInfo(userInfos);
    IAM_LOGI("end");
}

void FuzzGetCredentialById(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t credentialId = parcel.ReadUint64();
    EngCredentialInfo info;
    (void)GetUserAuthEngine().GetCredentialById(credentialId, info);
    IAM_LOGI("end");
}

void FuzzClearUnavailableCredential(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<int32_t> userIds;
    FillFuzzInt32Vector(parcel, userIds);
    std::vector<EngCredentialInfo> infos;
    (void)GetUserAuthEngine().ClearUnavailableCredential(userIds, infos);
    IAM_LOGI("end");
}

void FuzzUpdateAbandonResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> scheduleResult;
    Common::FillFuzzUint8Vector(parcel, scheduleResult);
    std::vector<EngCredentialInfo> infos;
    (void)GetUserAuthEngine().UpdateAbandonResult(userId, scheduleResult, infos);
    IAM_LOGI("end");
}

void FuzzBeginIdentification(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    int32_t authType = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    Common::FillFuzzUint8Vector(parcel, challenge);
    uint32_t executorSensorHint = parcel.ReadUint32();
    EngScheduleInfo scheduleInfo;
    (void)GetUserAuthEngine().BeginIdentification(contextId, authType, challenge, executorSensorHint, scheduleInfo);
    IAM_LOGI("end");
}

void FuzzUpdateIdentificationResult(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    std::vector<uint8_t> scheduleResult;
    Common::FillFuzzUint8Vector(parcel, scheduleResult);
    EngIdentifyResultInfo info;
    (void)GetUserAuthEngine().UpdateIdentificationResult(contextId, scheduleResult, info);
    IAM_LOGI("end");
}

void FuzzCancelIdentification(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    (void)GetUserAuthEngine().CancelIdentification(contextId);
    IAM_LOGI("end");
}

void FuzzBeginEnrollmentExt(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> authToken;
    Common::FillFuzzUint8Vector(parcel, authToken);
    EngEnrollParamExt param;
    FillEngEnrollParamExt(parcel, param);
    EngScheduleInfo info;
    (void)GetUserAuthEngine().BeginEnrollmentExt(authToken, param, info);
    IAM_LOGI("end");
}

void FuzzBeginAuthenticationExt(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    EngAuthParamExt param;
    FillEngAuthParamExt(parcel, param);
    std::vector<EngScheduleInfo> scheduleInfos;
    (void)GetUserAuthEngine().BeginAuthenticationExt(contextId, param, scheduleInfos);
    IAM_LOGI("end");
}

void FuzzSendMessage(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t scheduleId = parcel.ReadUint64();
    int32_t srcRole = parcel.ReadInt32();
    std::vector<uint8_t> msg;
    Common::FillFuzzUint8Vector(parcel, msg);
    (void)GetUserAuthEngine().SendMessage(scheduleId, srcRole, msg);
    IAM_LOGI("end");
}

void FuzzGetSignedExecutorInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<int32_t> authTypes;
    FillFuzzInt32Vector(parcel, authTypes);
    int32_t executorRole = parcel.ReadInt32();
    std::string remoteUdid;
    Common::FillFuzzString(parcel, remoteUdid);
    std::vector<uint8_t> signedExecutorInfo;
    (void)GetUserAuthEngine().GetSignedExecutorInfo(authTypes, executorRole, remoteUdid, signedExecutorInfo);
    IAM_LOGI("end");
}

void FuzzPrepareRemoteAuth(Parcel &parcel)
{
    IAM_LOGI("start");
    std::string remoteUdid;
    Common::FillFuzzString(parcel, remoteUdid);
    (void)GetUserAuthEngine().PrepareRemoteAuth(remoteUdid);
    IAM_LOGI("end");
}

void FuzzGetEnrolledState(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    int32_t authType = parcel.ReadInt32();
    EngEnrolledState enrolledState;
    (void)GetUserAuthEngine().GetEnrolledState(userId, authType, enrolledState);
    IAM_LOGI("end");
}

void FuzzSetGlobalConfigParam(Parcel &parcel)
{
    IAM_LOGI("start");
    EngGlobalConfigParam param;
    FillEngGlobalConfigParam(parcel, param);
    (void)GetUserAuthEngine().SetGlobalConfigParam(param);
    IAM_LOGI("end");
}

void FuzzVerifyAuthToken(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> tokenIn;
    Common::FillFuzzUint8Vector(parcel, tokenIn);
    uint64_t allowableDuration = parcel.ReadUint64();
    EngUserAuthTokenPlain tokenPlainOut;
    std::vector<uint8_t> rootSecret;
    (void)GetUserAuthEngine().VerifyAuthToken(tokenIn, allowableDuration, tokenPlainOut, rootSecret);
    IAM_LOGI("end");
}

void FuzzGetValidSolution(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    std::vector<int32_t> authTypes;
    FillFuzzInt32Vector(parcel, authTypes);
    uint32_t authTrustLevel = parcel.ReadUint32();
    std::vector<int32_t> validTypes;
    (void)GetUserAuthEngine().GetValidSolution(userId, authTypes, authTrustLevel, validTypes);
    IAM_LOGI("end");
}

void FuzzCheckReuseUnlockResult(Parcel &parcel)
{
    IAM_LOGI("start");
    EngReuseUnlockParam reuseParam;
    FillEngReuseUnlockParam(parcel, reuseParam);
    EngReuseUnlockInfo reuseInfo;
    (void)GetUserAuthEngine().CheckReuseUnlockResult(reuseParam, reuseInfo);
    IAM_LOGI("end");
}

void FuzzGetLocalScheduleFromMessage(Parcel &parcel)
{
    IAM_LOGI("start");
    std::string remoteUdid;
    Common::FillFuzzString(parcel, remoteUdid);
    std::vector<uint8_t> message;
    Common::FillFuzzUint8Vector(parcel, message);
    EngScheduleInfo scheduleInfo;
    (void)GetUserAuthEngine().GetLocalScheduleFromMessage(remoteUdid, message, scheduleInfo);
    IAM_LOGI("end");
}

void FuzzGetAuthResultFromMessage(Parcel &parcel)
{
    IAM_LOGI("start");
    std::string remoteUdid;
    Common::FillFuzzString(parcel, remoteUdid);
    std::vector<uint8_t> message;
    Common::FillFuzzUint8Vector(parcel, message);
    EngAuthResultInfo authResultInfo;
    (void)GetUserAuthEngine().GetAuthResultFromMessage(remoteUdid, message, authResultInfo);
    IAM_LOGI("end");
}

void FuzzLoad(Parcel &parcel)
{
    IAM_LOGI("start");
    (void)GetUserAuthEngine().Load();
    IAM_LOGI("end");
}

void FuzzUnload(Parcel &parcel)
{
    IAM_LOGI("start");
    (void)GetUserAuthEngine().Unload();
    IAM_LOGI("end");
}

void FuzzIsWidgetCallerAllowedOnLockScreen(Parcel &parcel)
{
    IAM_LOGI("start");
    EngCallerAuthInfo callerInfo;
    Common::FillFuzzString(parcel, callerInfo.callerName);
    callerInfo.callerType = parcel.ReadInt32();
    Common::FillFuzzString(parcel, callerInfo.appIdentifier);
    (void)GetUserAuthEngine().IsWidgetCallerAllowedOnLockScreen(callerInfo);
    IAM_LOGI("end");
}

// ---- dispatch table ---------------------------------------------------------

using FuzzFunc = void (*)(Parcel &);
FuzzFunc g_FuzzFuncs[] = {
    FuzzInit,
    FuzzAddExecutor,
    FuzzDeleteExecutor,
    FuzzOpenSession,
    FuzzCloseSession,
    FuzzBeginEnrollment,
    FuzzUpdateEnrollmentResult,
    FuzzCancelEnrollment,
    FuzzBeginAuthentication,
    FuzzUpdateAuthenticationResult,
    FuzzCancelAuthentication,
    FuzzGetCredential,
    FuzzDeleteCredential,
    FuzzGetAvailableStatus,
    FuzzGetUserInfo,
    FuzzDeleteUser,
    FuzzEnforceDeleteUser,
    FuzzGetAllExtUserInfo,
    FuzzGetCredentialById,
    FuzzClearUnavailableCredential,
    FuzzUpdateAbandonResult,
    FuzzBeginIdentification,
    FuzzUpdateIdentificationResult,
    FuzzCancelIdentification,
    FuzzBeginEnrollmentExt,
    FuzzBeginAuthenticationExt,
    FuzzSendMessage,
    FuzzGetSignedExecutorInfo,
    FuzzPrepareRemoteAuth,
    FuzzGetEnrolledState,
    FuzzSetGlobalConfigParam,
    FuzzVerifyAuthToken,
    FuzzGetValidSolution,
    FuzzCheckReuseUnlockResult,
    FuzzGetLocalScheduleFromMessage,
    FuzzGetAuthResultFromMessage,
    FuzzLoad,
    FuzzUnload,
    FuzzIsWidgetCallerAllowedOnLockScreen,
};

} // namespace

void HdiEngineFuzzTest(Parcel &parcel)
{
    uint32_t index = parcel.ReadUint32() % (sizeof(g_FuzzFuncs) / sizeof(FuzzFunc));
    auto fuzzFunc = g_FuzzFuncs[index];
    fuzzFunc(parcel);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    OHOS::UserIam::UserAuth::HdiEngineFuzzTest(parcel);
    return 0;
}

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

#include "hdi_type_convert.h"

#include "hdf_base.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

int32_t HdfCodeToResult(int32_t hdfCode)
{
    if (hdfCode >= 0) {
        return hdfCode;
    }
    switch (hdfCode) {
        case HDF_ERR_INVALID_PARAM:
            return ResultCode::INVALID_PARAMETERS;
        case HDF_ERR_NOT_SUPPORT:
            return ResultCode::TYPE_NOT_SUPPORT;
        case HDF_ERR_TIMEOUT:
            return ResultCode::TIMEOUT;
        case HDF_ERR_DEVICE_BUSY:
            return ResultCode::BUSY;
        case HDF_ERR_NOPERM:
            return ResultCode::CHECK_PERMISSION_FAILED;
        default:
            return ResultCode::GENERAL_ERROR;
    }
}

// ---- V4_0 conversions ------------------------------------------------------

// ---- CoAuthInterface::ExecutorRegisterInfo
HdiExecutorRegisterInfo EngToHdi(const CoAuthInterface::ExecutorRegisterInfo &info)
{
    HdiExecutorRegisterInfo hdi;
    hdi.authType = static_cast<int32_t>(info.authType);
    hdi.executorRole = static_cast<int32_t>(info.executorRole);
    hdi.executorSensorHint = info.executorSensorHint;
    hdi.executorMatcher = info.executorMatcher;
    hdi.esl = static_cast<int32_t>(info.esl);
    hdi.maxTemplateAcl = info.maxTemplateAcl;
    hdi.publicKey = info.publicKey;
    hdi.deviceUdid = info.deviceUdid;
    hdi.signedRemoteExecutorInfo = info.signedRemoteExecutorInfo;
    return hdi;
}

CoAuthInterface::ExecutorRegisterInfo HdiToEng(const HdiExecutorRegisterInfo &hdi)
{
    CoAuthInterface::ExecutorRegisterInfo eng;
    eng.authType = static_cast<AuthType>(hdi.authType);
    eng.executorRole = static_cast<ExecutorRole>(hdi.executorRole);
    eng.executorSensorHint = hdi.executorSensorHint;
    eng.executorMatcher = hdi.executorMatcher;
    eng.esl = static_cast<ExecutorSecureLevel>(hdi.esl);
    eng.maxTemplateAcl = hdi.maxTemplateAcl;
    eng.publicKey = hdi.publicKey;
    eng.deviceUdid = hdi.deviceUdid;
    eng.signedRemoteExecutorInfo = hdi.signedRemoteExecutorInfo;
    return eng;
}

// ---- EngExecutorSendMsg ----------------------------------------------------
HdiExecutorSendMsg EngToHdi(const EngExecutorSendMsg &eng)
{
    HdiExecutorSendMsg hdi;
    hdi.executorIndex = eng.executorIndex;
    hdi.commandId = eng.commandId;
    hdi.msg = eng.msg;
    return hdi;
}

EngExecutorSendMsg HdiToEng(const HdiExecutorSendMsg &hdi)
{
    EngExecutorSendMsg eng;
    eng.executorIndex = hdi.executorIndex;
    eng.commandId = hdi.commandId;
    eng.msg = hdi.msg;
    return eng;
}

// ---- EngAuthResultInfo (nested: msgs) --------------------------------------
HdiAuthResultInfo EngToHdi(const EngAuthResultInfo &eng)
{
    HdiAuthResultInfo hdi;
    hdi.result = eng.result;
    hdi.lockoutDuration = eng.lockoutDuration;
    hdi.remainAttempts = eng.remainAttempts;
    hdi.msgs = VecEngToHdi<EngExecutorSendMsg, HdiExecutorSendMsg>(eng.msgs);
    hdi.token = eng.token;
    hdi.rootSecret = eng.rootSecret;
    hdi.userId = eng.userId;
    hdi.credentialId = eng.credentialId;
    hdi.pinExpiredInfo = eng.pinExpiredInfo;
    hdi.remoteAuthResultMsg = eng.remoteAuthResultMsg;
    hdi.reEnrollFlag = eng.reEnrollFlag;
    return hdi;
}

EngAuthResultInfo HdiToEng(const HdiAuthResultInfo &hdi)
{
    EngAuthResultInfo eng;
    eng.result = hdi.result;
    eng.lockoutDuration = hdi.lockoutDuration;
    eng.remainAttempts = hdi.remainAttempts;
    eng.msgs = VecHdiToEng<EngExecutorSendMsg, HdiExecutorSendMsg>(hdi.msgs);
    eng.token = hdi.token;
    eng.rootSecret = hdi.rootSecret;
    eng.userId = hdi.userId;
    eng.credentialId = hdi.credentialId;
    eng.pinExpiredInfo = hdi.pinExpiredInfo;
    eng.remoteAuthResultMsg = hdi.remoteAuthResultMsg;
    eng.reEnrollFlag = hdi.reEnrollFlag;
    return eng;
}

// ---- EngIdentifyResultInfo -------------------------------------------------
HdiIdentifyResultInfo EngToHdi(const EngIdentifyResultInfo &eng)
{
    HdiIdentifyResultInfo hdi;
    hdi.result = eng.result;
    hdi.userId = eng.userId;
    hdi.token = eng.token;
    return hdi;
}

EngIdentifyResultInfo HdiToEng(const HdiIdentifyResultInfo &hdi)
{
    EngIdentifyResultInfo eng;
    eng.result = hdi.result;
    eng.userId = hdi.userId;
    eng.token = hdi.token;
    return eng;
}

// ---- EngCredentialInfo -----------------------------------------------------
HdiCredentialInfo EngToHdi(const EngCredentialInfo &eng)
{
    HdiCredentialInfo hdi;
    hdi.credentialId = eng.credentialId;
    hdi.executorIndex = eng.executorIndex;
    hdi.templateId = eng.templateId;
    hdi.authType = eng.authType;
    hdi.executorMatcher = eng.executorMatcher;
    hdi.executorSensorHint = eng.executorSensorHint;
    hdi.authSubType = eng.authSubType;
    hdi.isAbandoned = eng.isAbandoned;
    hdi.validityPeriod = eng.validityPeriod;
    return hdi;
}

EngCredentialInfo HdiToEng(const HdiCredentialInfo &hdi)
{
    EngCredentialInfo eng;
    eng.credentialId = hdi.credentialId;
    eng.executorIndex = hdi.executorIndex;
    eng.templateId = hdi.templateId;
    eng.authType = hdi.authType;
    eng.executorMatcher = hdi.executorMatcher;
    eng.executorSensorHint = hdi.executorSensorHint;
    eng.authSubType = hdi.authSubType;
    eng.isAbandoned = hdi.isAbandoned;
    eng.validityPeriod = hdi.validityPeriod;
    return eng;
}

// ---- EnrolledInfo (= SDK EnrolledInfo) ----------------------------------
// SDK declares authType, enrolledId; HDI declares enrolledId first — copy by
// name.
HdiEnrolledInfo EngToHdi(const EnrolledInfo &eng)
{
    HdiEnrolledInfo hdi;
    hdi.authType = eng.authType;
    hdi.enrolledId = eng.enrolledId;
    return hdi;
}

EnrolledInfo HdiToEng(const HdiEnrolledInfo &hdi)
{
    EnrolledInfo eng;
    eng.authType = static_cast<AuthType>(hdi.authType);
    eng.enrolledId = hdi.enrolledId;
    return eng;
}

// ---- EngEnrollResultInfo (nested: oldInfo) ---------------------------------
HdiEnrollResultInfo EngToHdi(const EngEnrollResultInfo &eng)
{
    HdiEnrollResultInfo hdi;
    hdi.credentialId = eng.credentialId;
    hdi.oldInfo = EngToHdi(eng.oldInfo);
    hdi.rootSecret = eng.rootSecret;
    hdi.oldRootSecret = eng.oldRootSecret;
    hdi.authToken = eng.authToken;
    return hdi;
}

EngEnrollResultInfo HdiToEng(const HdiEnrollResultInfo &hdi)
{
    EngEnrollResultInfo eng;
    eng.credentialId = hdi.credentialId;
    eng.oldInfo = HdiToEng(hdi.oldInfo);
    eng.rootSecret = hdi.rootSecret;
    eng.oldRootSecret = hdi.oldRootSecret;
    eng.authToken = hdi.authToken;
    return eng;
}

// ---- EngScheduleInfo -------------------------------------------------------
HdiScheduleInfo EngToHdi(const EngScheduleInfo &eng)
{
    HdiScheduleInfo hdi;
    hdi.scheduleId = eng.scheduleId;
    hdi.templateIds = eng.templateIds;
    hdi.authType = eng.authType;
    hdi.executorMatcher = eng.executorMatcher;
    hdi.scheduleMode = eng.scheduleMode;
    hdi.executorIndexes = eng.executorIndexes;
    hdi.executorMessages = eng.executorMessages;
    return hdi;
}

EngScheduleInfo HdiToEng(const HdiScheduleInfo &hdi)
{
    EngScheduleInfo eng;
    eng.scheduleId = hdi.scheduleId;
    eng.templateIds = hdi.templateIds;
    eng.authType = hdi.authType;
    eng.executorMatcher = hdi.executorMatcher;
    eng.scheduleMode = hdi.scheduleMode;
    eng.executorIndexes = hdi.executorIndexes;
    eng.executorMessages = hdi.executorMessages;
    return eng;
}

// ---- EngUserInfo (nested: enrolledInfos) -----------------------------------
HdiUserInfo EngToHdi(const EngUserInfo &eng)
{
    HdiUserInfo hdi;
    hdi.secureUid = eng.secureUid;
    hdi.pinSubType = eng.pinSubType;
    hdi.enrolledInfos = VecEngToHdi<EnrolledInfo, HdiEnrolledInfo>(eng.enrolledInfos);
    return hdi;
}

EngUserInfo HdiToEng(const HdiUserInfo &hdi)
{
    EngUserInfo eng;
    eng.secureUid = hdi.secureUid;
    eng.pinSubType = hdi.pinSubType;
    eng.enrolledInfos = VecHdiToEng<EnrolledInfo, HdiEnrolledInfo>(hdi.enrolledInfos);
    return eng;
}

// ---- EngExtUserInfo (nested: userInfo) -------------------------------------
HdiExtUserInfo EngToHdi(const EngExtUserInfo &eng)
{
    HdiExtUserInfo hdi;
    hdi.userId = eng.userId;
    hdi.userInfo = EngToHdi(eng.userInfo);
    return hdi;
}

EngExtUserInfo HdiToEng(const HdiExtUserInfo &hdi)
{
    EngExtUserInfo eng;
    eng.userId = hdi.userId;
    eng.userInfo = HdiToEng(hdi.userInfo);
    return eng;
}

// ---- EngAuthParamBase ------------------------------------------------------
HdiAuthParamBase EngToHdi(const EngAuthParamBase &eng)
{
    HdiAuthParamBase hdi;
    hdi.userId = eng.userId;
    hdi.authTrustLevel = eng.authTrustLevel;
    hdi.executorSensorHint = eng.executorSensorHint;
    hdi.challenge = eng.challenge;
    hdi.callerName = eng.callerName;
    hdi.callerType = eng.callerType;
    hdi.apiVersion = eng.apiVersion;
    return hdi;
}

EngAuthParamBase HdiToEng(const HdiAuthParamBase &hdi)
{
    EngAuthParamBase eng;
    eng.userId = hdi.userId;
    eng.authTrustLevel = hdi.authTrustLevel;
    eng.executorSensorHint = hdi.executorSensorHint;
    eng.challenge = hdi.challenge;
    eng.callerName = hdi.callerName;
    eng.callerType = hdi.callerType;
    eng.apiVersion = hdi.apiVersion;
    return eng;
}

// ---- EngAuthParam (nested: baseParam) --------------------------------------
HdiAuthParam EngToHdi(const EngAuthParam &eng)
{
    HdiAuthParam hdi;
    hdi.baseParam = EngToHdi(eng.baseParam);
    hdi.authType = eng.authType;
    hdi.authIntent = eng.authIntent;
    hdi.isOsAccountVerified = eng.isOsAccountVerified;
    hdi.collectorUdid = eng.collectorUdid;
    return hdi;
}

EngAuthParam HdiToEng(const HdiAuthParam &hdi)
{
    EngAuthParam eng;
    eng.baseParam = HdiToEng(hdi.baseParam);
    eng.authType = hdi.authType;
    eng.authIntent = hdi.authIntent;
    eng.isOsAccountVerified = hdi.isOsAccountVerified;
    eng.collectorUdid = hdi.collectorUdid;
    return eng;
}

// ---- EngReuseUnlockParam (nested: baseParam) -------------------------------
HdiReuseUnlockParam EngToHdi(const EngReuseUnlockParam &eng)
{
    HdiReuseUnlockParam hdi;
    hdi.baseParam = EngToHdi(eng.baseParam);
    hdi.authTypes = eng.authTypes;
    hdi.reuseUnlockResultDuration = eng.reuseUnlockResultDuration;
    hdi.reuseUnlockResultMode = eng.reuseUnlockResultMode;
    return hdi;
}

EngReuseUnlockParam HdiToEng(const HdiReuseUnlockParam &hdi)
{
    EngReuseUnlockParam eng;
    eng.baseParam = HdiToEng(hdi.baseParam);
    eng.authTypes = hdi.authTypes;
    eng.reuseUnlockResultDuration = hdi.reuseUnlockResultDuration;
    eng.reuseUnlockResultMode = hdi.reuseUnlockResultMode;
    return eng;
}

// ---- EngEnrollParam --------------------------------------------------------
HdiEnrollParam EngToHdi(const EngEnrollParam &eng)
{
    HdiEnrollParam hdi;
    hdi.authType = eng.authType;
    hdi.executorSensorHint = eng.executorSensorHint;
    hdi.callerName = eng.callerName;
    hdi.callerType = eng.callerType;
    hdi.apiVersion = eng.apiVersion;
    hdi.userId = eng.userId;
    hdi.userType = eng.userType;
    hdi.authSubType = eng.authSubType;
    return hdi;
}

EngEnrollParam HdiToEng(const HdiEnrollParam &hdi)
{
    EngEnrollParam eng;
    eng.authType = hdi.authType;
    eng.executorSensorHint = hdi.executorSensorHint;
    eng.callerName = hdi.callerName;
    eng.callerType = hdi.callerType;
    eng.apiVersion = hdi.apiVersion;
    eng.userId = hdi.userId;
    eng.userType = hdi.userType;
    eng.authSubType = hdi.authSubType;
    return eng;
}

// ---- EngEnrolledState (= EnrolledState) ------------------------------------
HdiEnrolledState EngToHdi(const EngEnrolledState &eng)
{
    HdiEnrolledState hdi;
    hdi.credentialDigest = eng.credentialDigest;
    hdi.credentialCount = eng.credentialCount;
    return hdi;
}

EngEnrolledState HdiToEng(const HdiEnrolledState &hdi)
{
    EngEnrolledState eng;
    eng.credentialDigest = hdi.credentialDigest;
    eng.credentialCount = hdi.credentialCount;
    return eng;
}

// ---- EngReuseUnlockInfo (nested: enrolledState) ----------------------------
HdiReuseUnlockInfo EngToHdi(const EngReuseUnlockInfo &eng)
{
    HdiReuseUnlockInfo hdi;
    hdi.authType = eng.authType;
    hdi.token = eng.token;
    hdi.enrolledState = EngToHdi(eng.enrolledState);
    return hdi;
}

EngReuseUnlockInfo HdiToEng(const HdiReuseUnlockInfo &hdi)
{
    EngReuseUnlockInfo eng;
    eng.authType = hdi.authType;
    eng.token = hdi.token;
    eng.enrolledState = HdiToEng(hdi.enrolledState);
    return eng;
}

// ---- EngGlobalConfigParam -------------------------------------------------
HdiGlobalConfigParam EngToHdi(const EngGlobalConfigParam &eng)
{
    HdiGlobalConfigParam hdi;
    hdi.type = eng.type;
    // Copy the union's active member based on the config type; accessing the
    // inactive member would be undefined behaviour.
    if (eng.type == static_cast<int32_t>(EngGlobalConfigType::ENABLE_STATUS)) {
        hdi.value.enableStatus = eng.value.enableStatus;
    } else {
        hdi.value.pinExpiredPeriod = eng.value.pinExpiredPeriod;
    }
    hdi.userIds = eng.userIds;
    hdi.authTypes = eng.authTypes;
    return hdi;
}

EngGlobalConfigParam HdiToEng(const HdiGlobalConfigParam &hdi)
{
    EngGlobalConfigParam eng;
    eng.type = hdi.type;
    if (hdi.type == static_cast<int32_t>(EngGlobalConfigType::ENABLE_STATUS)) {
        eng.value.enableStatus = hdi.value.enableStatus;
    } else {
        eng.value.pinExpiredPeriod = hdi.value.pinExpiredPeriod;
    }
    eng.userIds = hdi.userIds;
    eng.authTypes = hdi.authTypes;
    return eng;
}

// ---- EngUserAuthTokenPlain -------------------------------------------------
HdiUserAuthTokenPlain EngToHdi(const EngUserAuthTokenPlain &eng)
{
    HdiUserAuthTokenPlain hdi;
    hdi.version = eng.version;
    hdi.userId = eng.userId;
    hdi.challenge = eng.challenge;
    hdi.timeInterval = eng.timeInterval;
    hdi.authTrustLevel = eng.authTrustLevel;
    hdi.authType = eng.authType;
    hdi.authMode = eng.authMode;
    hdi.securityLevel = eng.securityLevel;
    hdi.tokenType = eng.tokenType;
    hdi.secureUid = eng.secureUid;
    hdi.enrolledId = eng.enrolledId;
    hdi.credentialId = eng.credentialId;
    hdi.collectorUdid = eng.collectorUdid;
    hdi.verifierUdid = eng.verifierUdid;
    return hdi;
}

EngUserAuthTokenPlain HdiToEng(const HdiUserAuthTokenPlain &hdi)
{
    EngUserAuthTokenPlain eng;
    eng.version = hdi.version;
    eng.userId = hdi.userId;
    eng.challenge = hdi.challenge;
    eng.timeInterval = hdi.timeInterval;
    eng.authTrustLevel = hdi.authTrustLevel;
    eng.authType = hdi.authType;
    eng.authMode = hdi.authMode;
    eng.securityLevel = hdi.securityLevel;
    eng.tokenType = hdi.tokenType;
    eng.secureUid = hdi.secureUid;
    eng.enrolledId = hdi.enrolledId;
    eng.credentialId = hdi.credentialId;
    eng.collectorUdid = hdi.collectorUdid;
    eng.verifierUdid = hdi.verifierUdid;
    return eng;
}

// ---- EngCredentialOperateResult (special: operateType enum<->int32_t) -----
// Nested: scheduleInfo, credentialInfos.
HdiCredentialOperateResult EngToHdi(const EngCredentialOperateResult &eng)
{
    HdiCredentialOperateResult hdi;
    hdi.operateType = static_cast<HdiCredentialOperateType>(eng.operateType);
    hdi.scheduleInfo = EngToHdi(eng.scheduleInfo);
    hdi.credentialInfos =
        VecEngToHdi<EngCredentialInfo, HdiCredentialInfo>(eng.credentialInfos);
    return hdi;
}

EngCredentialOperateResult HdiToEng(const HdiCredentialOperateResult &hdi)
{
    EngCredentialOperateResult eng;
    eng.operateType = static_cast<int32_t>(hdi.operateType);
    eng.scheduleInfo = HdiToEng(hdi.scheduleInfo);
    eng.credentialInfos =
        VecHdiToEng<EngCredentialInfo, HdiCredentialInfo>(hdi.credentialInfos);
    return eng;
}

// ---- V4_1 conversions ------------------------------------------------------

// ---- EngAuthParamExt (nested: baseParam, V4_0 type) ------------------------
HdiAuthParamExt EngToHdi(const EngAuthParamExt &eng)
{
    HdiAuthParamExt hdi;
    hdi.baseParam = EngToHdi(eng.baseParam);
    hdi.authType = eng.authType;
    hdi.authIntent = eng.authIntent;
    hdi.isOsAccountVerified = eng.isOsAccountVerified;
    hdi.collectorUdid = eng.collectorUdid;
    hdi.credentialIdList = eng.credentialIdList;
    return hdi;
}

EngAuthParamExt HdiToEng(const HdiAuthParamExt &hdi)
{
    EngAuthParamExt eng;
    eng.baseParam = HdiToEng(hdi.baseParam);
    eng.authType = hdi.authType;
    eng.authIntent = hdi.authIntent;
    eng.isOsAccountVerified = hdi.isOsAccountVerified;
    eng.collectorUdid = hdi.collectorUdid;
    eng.credentialIdList = hdi.credentialIdList;
    return eng;
}

// ---- EngEnrollParamExt -----------------------------------------------------
HdiEnrollParamExt EngToHdi(const EngEnrollParamExt &eng)
{
    HdiEnrollParamExt hdi;
    hdi.authType = eng.authType;
    hdi.executorSensorHint = eng.executorSensorHint;
    hdi.callerName = eng.callerName;
    hdi.callerType = eng.callerType;
    hdi.apiVersion = eng.apiVersion;
    hdi.userId = eng.userId;
    hdi.userType = eng.userType;
    hdi.authSubType = eng.authSubType;
    hdi.additionalInfo = eng.additionalInfo;
    return hdi;
}

EngEnrollParamExt HdiToEng(const HdiEnrollParamExt &hdi)
{
    EngEnrollParamExt eng;
    eng.authType = hdi.authType;
    eng.executorSensorHint = hdi.executorSensorHint;
    eng.callerName = hdi.callerName;
    eng.callerType = hdi.callerType;
    eng.apiVersion = hdi.apiVersion;
    eng.userId = hdi.userId;
    eng.userType = hdi.userType;
    eng.authSubType = hdi.authSubType;
    eng.additionalInfo = hdi.additionalInfo;
    return eng;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

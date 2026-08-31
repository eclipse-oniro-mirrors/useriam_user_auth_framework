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

#define LOG_FILE_ID LOG_FILE_HDI_WRAPPER

#include "hdi_type_convert_fuzzer.h"
#include "hdi_type_convert.h"

#include <cstdint>
#include <string>
#include <vector>

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "parcel.h"

#include "hdi_type_aliases.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

// ---- helpers: fill HDI types from Parcel ------------------------------------

void FillExecutorSendMsg(Parcel &parcel,
    HdiExecutorSendMsg &msg)
{
    msg.executorIndex = parcel.ReadUint64();
    msg.commandId = parcel.ReadInt32();
    Common::FillFuzzUint8Vector(parcel, msg.msg);
}

void FillEnrolledInfo(Parcel &parcel,
    HdiEnrolledInfo &info)
{
    info.authType = parcel.ReadInt32();
    info.enrolledId = parcel.ReadUint64();
}

void FillEnrolledState(Parcel &parcel,
    HdiEnrolledState &state)
{
    state.credentialDigest = parcel.ReadUint64();
    state.credentialCount = parcel.ReadUint16();
}

void FillAuthParamBase(Parcel &parcel,
    HdiAuthParamBase &base)
{
    base.userId = parcel.ReadInt32();
    base.authTrustLevel = parcel.ReadUint32();
    base.executorSensorHint = parcel.ReadUint32();
    Common::FillFuzzUint8Vector(parcel, base.challenge);
    Common::FillFuzzString(parcel, base.callerName);
    base.callerType = parcel.ReadInt32();
    base.apiVersion = parcel.ReadInt32();
}

// ---- individual fuzz functions ---------------------------------------------

void FuzzHdfCodeToResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t hdfCode = parcel.ReadInt32();
    (void)HdfCodeToResult(hdfCode);
    IAM_LOGI("end");
}

void FuzzExecutorRegisterInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiExecutorRegisterInfo hdi;
    hdi.authType = parcel.ReadInt32();
    hdi.executorRole = parcel.ReadInt32();
    hdi.executorSensorHint = parcel.ReadUint32();
    hdi.executorMatcher = parcel.ReadUint32();
    hdi.esl = parcel.ReadInt32();
    hdi.maxTemplateAcl = parcel.ReadUint64();
    Common::FillFuzzUint8Vector(parcel, hdi.publicKey);
    Common::FillFuzzString(parcel, hdi.deviceUdid);
    Common::FillFuzzUint8Vector(parcel, hdi.signedRemoteExecutorInfo);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzExecutorSendMsg(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiExecutorSendMsg hdi;
    FillExecutorSendMsg(parcel, hdi);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzAuthResultInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiAuthResultInfo hdi;
    hdi.result = parcel.ReadInt32();
    hdi.lockoutDuration = parcel.ReadInt32();
    hdi.remainAttempts = parcel.ReadInt32();
    {
        uint32_t count = parcel.ReadUint32() % 8;
        for (uint32_t i = 0; i < count; i++) {
            HdiExecutorSendMsg msg;
            FillExecutorSendMsg(parcel, msg);
            hdi.msgs.push_back(msg);
        }
    }
    Common::FillFuzzUint8Vector(parcel, hdi.token);
    Common::FillFuzzUint8Vector(parcel, hdi.rootSecret);
    hdi.userId = parcel.ReadInt32();
    hdi.credentialId = parcel.ReadUint64();
    hdi.pinExpiredInfo = parcel.ReadInt64();
    Common::FillFuzzUint8Vector(parcel, hdi.remoteAuthResultMsg);
    hdi.reEnrollFlag = parcel.ReadBool();
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzIdentifyResultInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiIdentifyResultInfo hdi;
    hdi.result = parcel.ReadInt32();
    hdi.userId = parcel.ReadInt32();
    Common::FillFuzzUint8Vector(parcel, hdi.token);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzCredentialInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiCredentialInfo hdi;
    hdi.credentialId = parcel.ReadUint64();
    hdi.executorIndex = parcel.ReadUint64();
    hdi.templateId = parcel.ReadUint64();
    hdi.authType = parcel.ReadInt32();
    hdi.executorMatcher = parcel.ReadUint32();
    hdi.executorSensorHint = parcel.ReadUint32();
    hdi.authSubType = parcel.ReadInt32();
    hdi.isAbandoned = parcel.ReadBool();
    hdi.validityPeriod = parcel.ReadInt64();
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzEnrolledInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiEnrolledInfo hdi;
    FillEnrolledInfo(parcel, hdi);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzEnrollResultInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiEnrollResultInfo hdi;
    hdi.credentialId = parcel.ReadUint64();
    {
        HdiCredentialInfo oldInfo;
        oldInfo.credentialId = parcel.ReadUint64();
        oldInfo.executorIndex = parcel.ReadUint64();
        oldInfo.templateId = parcel.ReadUint64();
        oldInfo.authType = parcel.ReadInt32();
        oldInfo.executorMatcher = parcel.ReadUint32();
        oldInfo.executorSensorHint = parcel.ReadUint32();
        oldInfo.authSubType = parcel.ReadInt32();
        oldInfo.isAbandoned = parcel.ReadBool();
        oldInfo.validityPeriod = parcel.ReadInt64();
        hdi.oldInfo = oldInfo;
    }
    Common::FillFuzzUint8Vector(parcel, hdi.rootSecret);
    Common::FillFuzzUint8Vector(parcel, hdi.oldRootSecret);
    Common::FillFuzzUint8Vector(parcel, hdi.authToken);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzScheduleInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiScheduleInfo hdi;
    hdi.scheduleId = parcel.ReadUint64();
    Common::FillFuzzUint64Vector(parcel, hdi.templateIds);
    hdi.authType = parcel.ReadInt32();
    hdi.executorMatcher = parcel.ReadUint32();
    hdi.scheduleMode = parcel.ReadInt32();
    Common::FillFuzzUint64Vector(parcel, hdi.executorIndexes);
    {
        uint32_t count = parcel.ReadUint32() % 8;
        for (uint32_t i = 0; i < count; i++) {
            std::vector<uint8_t> msg;
            Common::FillFuzzUint8Vector(parcel, msg);
            hdi.executorMessages.push_back(msg);
        }
    }
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzUserInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiUserInfo hdi;
    hdi.secureUid = parcel.ReadUint64();
    hdi.pinSubType = parcel.ReadInt32();
    {
        uint32_t count = parcel.ReadUint32() % 8;
        for (uint32_t i = 0; i < count; i++) {
            HdiEnrolledInfo info;
            FillEnrolledInfo(parcel, info);
            hdi.enrolledInfos.push_back(info);
        }
    }
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzExtUserInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiExtUserInfo hdi;
    hdi.userId = parcel.ReadInt32();
    {
        HdiUserInfo userInfo;
        userInfo.secureUid = parcel.ReadUint64();
        userInfo.pinSubType = parcel.ReadInt32();
        uint32_t count = parcel.ReadUint32() % 8;
        for (uint32_t i = 0; i < count; i++) {
            HdiEnrolledInfo info;
            FillEnrolledInfo(parcel, info);
            userInfo.enrolledInfos.push_back(info);
        }
        hdi.userInfo = userInfo;
    }
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzAuthParamBase(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiAuthParamBase hdi;
    FillAuthParamBase(parcel, hdi);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzAuthParam(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiAuthParam hdi;
    FillAuthParamBase(parcel, hdi.baseParam);
    hdi.authType = parcel.ReadInt32();
    hdi.authIntent = parcel.ReadInt32();
    hdi.isOsAccountVerified = parcel.ReadBool();
    Common::FillFuzzString(parcel, hdi.collectorUdid);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzReuseUnlockParam(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiReuseUnlockParam hdi;
    FillAuthParamBase(parcel, hdi.baseParam);
    {
        uint32_t count = parcel.ReadUint32() % 8;
        for (uint32_t i = 0; i < count; i++) {
            hdi.authTypes.push_back(parcel.ReadInt32());
        }
    }
    hdi.reuseUnlockResultDuration = parcel.ReadUint64();
    hdi.reuseUnlockResultMode = parcel.ReadInt32();
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzEnrollParam(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiEnrollParam hdi;
    hdi.authType = parcel.ReadInt32();
    hdi.executorSensorHint = parcel.ReadUint32();
    Common::FillFuzzString(parcel, hdi.callerName);
    hdi.callerType = parcel.ReadInt32();
    hdi.apiVersion = parcel.ReadInt32();
    hdi.userId = parcel.ReadInt32();
    hdi.userType = parcel.ReadInt32();
    hdi.authSubType = parcel.ReadInt32();
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzEnrolledState(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiEnrolledState hdi;
    FillEnrolledState(parcel, hdi);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzReuseUnlockInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiReuseUnlockInfo hdi;
    hdi.authType = parcel.ReadInt32();
    Common::FillFuzzUint8Vector(parcel, hdi.token);
    FillEnrolledState(parcel, hdi.enrolledState);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzGlobalConfigParam(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiGlobalConfigParam hdi;
    hdi.type = parcel.ReadInt32();
    hdi.value.pinExpiredPeriod = parcel.ReadInt64();
    {
        uint32_t count = parcel.ReadUint32() % 8;
        for (uint32_t i = 0; i < count; i++) {
            hdi.userIds.push_back(parcel.ReadInt32());
        }
    }
    {
        uint32_t count = parcel.ReadUint32() % 8;
        for (uint32_t i = 0; i < count; i++) {
            hdi.authTypes.push_back(parcel.ReadInt32());
        }
    }
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzUserAuthTokenPlain(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiUserAuthTokenPlain hdi;
    hdi.version = parcel.ReadUint32();
    hdi.userId = parcel.ReadInt32();
    Common::FillFuzzUint8Vector(parcel, hdi.challenge);
    hdi.timeInterval = parcel.ReadUint64();
    hdi.authTrustLevel = parcel.ReadUint32();
    hdi.authType = parcel.ReadInt32();
    hdi.authMode = parcel.ReadInt32();
    hdi.securityLevel = parcel.ReadUint32();
    hdi.tokenType = parcel.ReadInt32();
    hdi.secureUid = parcel.ReadUint64();
    hdi.enrolledId = parcel.ReadUint64();
    hdi.credentialId = parcel.ReadUint64();
    Common::FillFuzzString(parcel, hdi.collectorUdid);
    Common::FillFuzzString(parcel, hdi.verifierUdid);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzCredentialOperateResult(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiCredentialOperateResult hdi;
    hdi.operateType = static_cast<HdiCredentialOperateType>(
        parcel.ReadInt32());
    {
        HdiScheduleInfo schedule;
        schedule.scheduleId = parcel.ReadUint64();
        Common::FillFuzzUint64Vector(parcel, schedule.templateIds);
        schedule.authType = parcel.ReadInt32();
        schedule.executorMatcher = parcel.ReadUint32();
        schedule.scheduleMode = parcel.ReadInt32();
        Common::FillFuzzUint64Vector(parcel, schedule.executorIndexes);
        {
            uint32_t count = parcel.ReadUint32() % 4;
            for (uint32_t i = 0; i < count; i++) {
                std::vector<uint8_t> msg;
                Common::FillFuzzUint8Vector(parcel, msg);
                schedule.executorMessages.push_back(msg);
            }
        }
        hdi.scheduleInfo = schedule;
    }
    {
        uint32_t count = parcel.ReadUint32() % 8;
        for (uint32_t i = 0; i < count; i++) {
            HdiCredentialInfo ci;
            ci.credentialId = parcel.ReadUint64();
            ci.executorIndex = parcel.ReadUint64();
            ci.templateId = parcel.ReadUint64();
            ci.authType = parcel.ReadInt32();
            ci.executorMatcher = parcel.ReadUint32();
            ci.executorSensorHint = parcel.ReadUint32();
            ci.authSubType = parcel.ReadInt32();
            ci.isAbandoned = parcel.ReadBool();
            ci.validityPeriod = parcel.ReadInt64();
            hdi.credentialInfos.push_back(ci);
        }
    }
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzAuthParamExt(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiAuthParamExt hdi;
    FillAuthParamBase(parcel, hdi.baseParam);
    hdi.authType = parcel.ReadInt32();
    hdi.authIntent = parcel.ReadInt32();
    hdi.isOsAccountVerified = parcel.ReadBool();
    Common::FillFuzzString(parcel, hdi.collectorUdid);
    Common::FillFuzzUint64Vector(parcel, hdi.credentialIdList);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

void FuzzEnrollParamExt(Parcel &parcel)
{
    IAM_LOGI("start");
    HdiEnrollParamExt hdi;
    hdi.authType = parcel.ReadInt32();
    hdi.executorSensorHint = parcel.ReadUint32();
    Common::FillFuzzString(parcel, hdi.callerName);
    hdi.callerType = parcel.ReadInt32();
    hdi.apiVersion = parcel.ReadInt32();
    hdi.userId = parcel.ReadInt32();
    hdi.userType = parcel.ReadInt32();
    hdi.authSubType = parcel.ReadInt32();
    Common::FillFuzzString(parcel, hdi.additionalInfo);
    auto eng = HdiToEng(hdi);
    (void)EngToHdi(eng);
    IAM_LOGI("end");
}

// ---- dispatch table ---------------------------------------------------------

using FuzzFunc = void (*)(Parcel &);
FuzzFunc g_FuzzFuncs[] = {
    FuzzHdfCodeToResult,
    FuzzExecutorRegisterInfo,
    FuzzExecutorSendMsg,
    FuzzAuthResultInfo,
    FuzzIdentifyResultInfo,
    FuzzCredentialInfo,
    FuzzEnrolledInfo,
    FuzzEnrollResultInfo,
    FuzzScheduleInfo,
    FuzzUserInfo,
    FuzzExtUserInfo,
    FuzzAuthParamBase,
    FuzzAuthParam,
    FuzzReuseUnlockParam,
    FuzzEnrollParam,
    FuzzEnrolledState,
    FuzzReuseUnlockInfo,
    FuzzGlobalConfigParam,
    FuzzUserAuthTokenPlain,
    FuzzCredentialOperateResult,
    FuzzAuthParamExt,
    FuzzEnrollParamExt,
};

} // namespace

void HdiTypeConvertFuzzTest(Parcel &parcel)
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
    OHOS::UserIam::UserAuth::HdiTypeConvertFuzzTest(parcel);
    return 0;
}

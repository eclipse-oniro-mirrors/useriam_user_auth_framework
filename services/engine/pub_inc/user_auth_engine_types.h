/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef USER_AUTH_ENGINE_TYPES_H
#define USER_AUTH_ENGINE_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

#include "co_auth_interface.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

enum EngUserType : int32_t {
    MAIN = 0,
    SUB = 1,
    PRIVATE = 2,
};

enum class EngGlobalConfigType : int32_t {
    PIN_EXPIRED_PERIOD = 1,
    ENABLE_STATUS = 2,
};

enum EngCredentialOperateType : int32_t {
    CREDENTIAL_DELETE = 1,
    CREDENTIAL_ABANDON = 2,
    PIN_UPDATE = 3,
};

// Caller-type contract passed to the auth engine / HDI driver. Mapped
// explicitly from ATokenType (see authentication_impl / enrollment_impl) so the
// value does not rely on ATokenType's numerics coinciding with the driver's.
enum EngCallerType : int32_t {
    ENG_CALLER_TYPE_INVALID = -1,
    ENG_CALLER_TYPE_HAP = 0,
    ENG_CALLER_TYPE_NATIVE = 1,
};

struct EngExecutorSendMsg {
    uint64_t executorIndex {};
    int32_t commandId {};
    std::vector<uint8_t> msg;
};

struct EngAuthResultInfo {
    int32_t result {};
    uint32_t authTrustLevel {};
    int32_t lockoutDuration {};
    int32_t remainAttempts {};
    std::vector<EngExecutorSendMsg> msgs;
    std::vector<uint8_t> token;
    std::vector<uint8_t> rootSecret;
    int32_t userId {};
    uint64_t credentialId {};
    int64_t pinExpiredInfo {};
    std::vector<uint8_t> remoteAuthResultMsg;
    bool reEnrollFlag {};
};

struct EngIdentifyResultInfo {
    int32_t result {};
    int32_t userId {};
    std::vector<uint8_t> token;
};

struct EngCredentialInfo {
    uint64_t credentialId {};
    uint64_t executorIndex {};
    uint64_t templateId {};
    int32_t authType {};
    uint32_t executorMatcher {};
    uint32_t executorSensorHint {};
    int32_t authSubType {};
    bool isAbandoned {};
    int64_t validityPeriod {};
} __attribute__((aligned(8)));

struct EngEnrollResultInfo {
    uint64_t credentialId {};
    EngCredentialInfo oldInfo;
    std::vector<uint8_t> rootSecret;
    std::vector<uint8_t> oldRootSecret;
    std::vector<uint8_t> authToken;
};

struct EngScheduleInfo {
    uint64_t scheduleId {};
    std::vector<uint64_t> templateIds;
    int32_t authType {};
    uint32_t executorMatcher {};
    int32_t scheduleMode {};
    std::vector<uint64_t> executorIndexes;
    std::vector<std::vector<uint8_t>> executorMessages;
};

struct EngUserInfo {
    uint64_t secureUid {};
    int32_t pinSubType {};
    std::vector<EnrolledInfo> enrolledInfos;
};

struct EngExtUserInfo {
    int32_t userId {};
    EngUserInfo userInfo;
};

struct EngAuthParamBase {
    int32_t userId {};
    uint32_t authTrustLevel {};
    uint32_t executorSensorHint {};
    std::vector<uint8_t> challenge;
    std::string callerName;
    int32_t callerType {};
    int32_t apiVersion {};
};

struct EngCallerAuthInfo {
    std::string callerName;
    int32_t callerType {};
    std::string appIdentifier;
};

struct EngAuthParam {
    EngAuthParamBase baseParam;
    int32_t authType {};
    int32_t authIntent {};
    bool isOsAccountVerified {};
    std::string collectorUdid;
};

struct EngAuthParamExt {
    EngAuthParamBase baseParam;
    int32_t authType {};
    int32_t authIntent {};
    bool isOsAccountVerified {};
    std::string collectorUdid;
    std::vector<uint64_t> credentialIdList;
};

struct EngReuseUnlockParam {
    EngAuthParamBase baseParam;
    std::vector<int32_t> authTypes;
    uint64_t reuseUnlockResultDuration {};
    int32_t reuseUnlockResultMode {};
};

struct EngEnrollParam {
    int32_t authType {};
    uint32_t executorSensorHint {};
    std::string callerName;
    int32_t callerType {};
    int32_t apiVersion {};
    int32_t userId {};
    int32_t userType {};
    int32_t authSubType {};
};

struct EngEnrollParamExt {
    int32_t authType {};
    uint32_t executorSensorHint {};
    std::string callerName;
    int32_t callerType {};
    int32_t apiVersion {};
    int32_t userId {};
    int32_t userType {};
    int32_t authSubType {};
    std::string additionalInfo;
};

struct EngEnrolledState {
    uint64_t credentialDigest {};
    uint16_t credentialCount {};
} __attribute__((aligned(8)));

struct EngReuseUnlockInfo {
    int32_t authType {};
    std::vector<uint8_t> token;
    EngEnrolledState enrolledState;
};

union EngGlobalConfigValue {
    int64_t pinExpiredPeriod {};
    bool enableStatus;
} __attribute__((aligned(8)));

struct EngGlobalConfigParam {
    int32_t type {};
    EngGlobalConfigValue value;
    std::vector<int32_t> userIds;
    std::vector<int32_t> authTypes;
};

struct EngUserAuthTokenPlain {
    uint32_t version {};
    int32_t userId {};
    std::vector<uint8_t> challenge;
    uint64_t timeInterval {};
    uint32_t authTrustLevel {};
    int32_t authType {};
    int32_t authMode {};
    uint32_t securityLevel {};
    int32_t tokenType {};
    uint64_t secureUid {};
    uint64_t enrolledId {};
    uint64_t credentialId {};
    std::string collectorUdid;
    std::string verifierUdid;
};

struct EngCredentialOperateResult {
    int32_t operateType {};
    EngScheduleInfo scheduleInfo;
    std::vector<EngCredentialInfo> credentialInfos;
};

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_AUTH_ENGINE_TYPES_H

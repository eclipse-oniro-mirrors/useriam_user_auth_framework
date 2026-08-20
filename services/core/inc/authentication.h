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

#ifndef IAM_AUTHENTICATION_H
#define IAM_AUTHENTICATION_H

#include <cstdint>
#include <memory>

#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Authentication {
public:
    struct AuthenticationPara {
        int32_t userId {0};
        AuthType authType {ALL};
        AuthTrustLevel atl {ATL1};
        uint32_t tokenId {0};
        uint32_t collectorTokenId {0};
        std::vector<uint8_t> challenge;
        bool endAfterFirstFail;
        std::string callerName;
        int32_t sdkVersion;
        int32_t callerType;
        int32_t authIntent;
        bool isOsAccountVerified;
        bool skipLockedBiometricAuth;
        std::vector<uint64_t> credentialIdList;
        std::string title;
        AuthScene authScene {AUTH_SCENE_DEFAULT};
    };

    struct AuthResultInfo {
        int32_t result;
        uint32_t authTrustLevel {0};
        int32_t freezingTime;
        int32_t remainTimes;
        std::vector<uint8_t> token;
        std::vector<uint8_t> rootSecret;
        uint64_t credentialDigest{0};
        uint16_t credentialCount{0};
        int32_t sdkVersion{0};
        int32_t userId;
        int32_t nextFailLockoutDuration;
        int64_t pinExpiredInfo;
        std::vector<uint8_t> remoteAuthResultMsg;
        uint64_t credentialId;
        bool reEnrollFlag;
    };
    struct AuthExecutorMsg {
        uint64_t executorIndex;
        int32_t commandId;
        std::vector<uint8_t> msg;
    };
    virtual ~Authentication() = default;

    virtual void SetExecutor(uint32_t executorIndex) = 0;
    virtual void SetChallenge(const std::vector<uint8_t> &challenge) = 0;
    virtual void SetAccessTokenId(uint32_t tokenId) = 0;
    virtual void SetEndAfterFirstFail(bool endAfterFirstFail) = 0;
    virtual void SetCollectorUdid(std::string &collectorUdid) = 0;

    virtual bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        std::shared_ptr<ScheduleNodeCallback> callback) = 0;
    virtual bool Update(const std::vector<uint8_t> &scheduleResult, AuthResultInfo &resultInfo) = 0;
    virtual std::vector<Authentication::AuthExecutorMsg> GetAuthExecutorMsgs() const = 0;
    virtual bool Cancel() = 0;
    virtual uint32_t GetAccessTokenId() const = 0;
    virtual int32_t GetLatestError() const = 0;
    virtual int32_t GetUserId() const = 0;
    virtual int32_t GetAuthType() const = 0;

protected:
    virtual void SetLatestError(int32_t error) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_AUTHENTICATION_H
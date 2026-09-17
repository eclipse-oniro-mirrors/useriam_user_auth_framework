/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DUMMY_AUTHENTICATION_H
#define DUMMY_AUTHENTICATION_H

#include "authentication.h"

#undef private

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyAuthentication : public Authentication {
public:
    void SetExecutor(uint32_t executorIndex){};
    void SetChallenge(const std::vector<uint8_t> &challenge){};
    void SetAccessTokenId(uint32_t tokenId){};
    void SetEndAfterFirstFail(bool endAfterFirstFail){};
    void SetCollectorUdid(std::string &collectorUdid){};
    void SetLatestError(int32_t error){};
    bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        AcquireInfoCallback &acquireInfoCallback, std::shared_ptr<ScheduleNodeCallback> callback)
        {
            return true;
        };
    bool Update(const std::vector<uint8_t> &scheduleResult,
        AuthResultInfo &resultInfo, AcquireInfoCallback &acquireInfoCallback)
        {
            return true;
        };
    std::vector<Authentication::AuthExecutorMsg> GetAuthExecutorMsgs() const
        {
            return {};
        };
    bool Cancel()
        {
            return true;
        };
    uint32_t GetAccessTokenId() const
    {
        return 0;
    };
    int32_t GetLatestError() const
    {
        return 0;
    };
    int32_t GetUserId() const
    {
        return 0;
    };
    int32_t GetAuthType() const
    {
        return 0;
    };
    void OnContextPoolInsert(const std::shared_ptr<Context> &context){};
    void OnContextPoolDelete(const std::shared_ptr<Context> &context){};
};
}
} // UserAuth
} // UserIam
} // OHOS

#endif // DUMMY_AUTHENICATION_H
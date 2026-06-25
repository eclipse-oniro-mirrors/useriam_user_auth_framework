/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#ifndef IAM_MOCK_CONTEXT_H
#define IAM_MOCK_CONTEXT_H

#include <memory>

#include <gmock/gmock.h>

#include "app_mgr_interface.h"
#include "context.h"
#include "context_callback.h"
#include "iam_ptr.h"
#include "mock_schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::AppExecFwk;
class MockContextCallback : public ContextCallback {
public:
    virtual ~MockContextCallback() = default;
    MOCK_METHOD2(NewInstance, std::shared_ptr<ContextCallback>(sptr<IIamCallback> iamCallback,
        OperationType operationType));
    MOCK_METHOD2(OnResult, void(int32_t resultCode, const Attributes &finalResult));
    MOCK_METHOD3(
        OnAcquireInfo, void(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg));
    MOCK_METHOD1(SetTraceCallerName, void(const std::string &callerName));
    MOCK_METHOD1(SetTraceRequestContextId, void(uint64_t requestContextId));
    MOCK_METHOD1(SetTraceAuthContextId, void(uint64_t authContextId));
    MOCK_METHOD1(SetTraceUserId, void(int32_t userId));
    MOCK_METHOD1(SetTraceRemainTime, void(int32_t remainTime));
    MOCK_METHOD1(SetTraceFreezingTime, void(int32_t freezingTime));
    MOCK_METHOD1(SetTraceSdkVersion, void(int32_t version));
    MOCK_METHOD1(SetTraceAuthType, void(int32_t authType));
    MOCK_METHOD1(SetTraceAuthWidgetType, void(uint32_t authWidgetType));
    MOCK_METHOD1(SetTraceAuthTrustLevel, void(AuthTrustLevel atl));
    MOCK_METHOD1(SetTraceReuseUnlockResultMode, void(uint32_t reuseUnlockResultMode));
    MOCK_METHOD1(SetTraceReuseUnlockResultDuration, void(uint64_t reuseUnlockResultDuration));
    MOCK_METHOD1(SetCleaner, void(Context::ContextStopCallback callback));
    MOCK_METHOD4(ParseAuthTipInfo, int32_t(int32_t tip, const std::vector<uint8_t> &extraInfo,
        int32_t &authResult, int32_t &freezingTime));
    MOCK_METHOD2(ProcessAuthResult, void(int32_t tip, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD0(GetIamCallback, sptr<IIamCallback>());
    MOCK_METHOD0(GetCallerName, std::string());
    MOCK_METHOD1(SetTraceCallerType, void(int32_t callerType));
    MOCK_METHOD1(SetTraceIsRemoteAuth, void(bool isRemoteAuth));
    MOCK_METHOD1(SetTraceRemoteUdid, void(const std::string &remoteUdid));
    MOCK_METHOD1(SetTraceLocalUdid, void(const std::string &LocalUdid));
    MOCK_METHOD1(SetTraceConnectionName, void(const std::string &connectionName));
    MOCK_METHOD1(SetTraceAuthFinishReason, void(const std::string &authFinishReason));
    MOCK_METHOD1(SetTraceIsBackgroundApplication, void(const bool isBackgroundApplication));
    MOCK_METHOD1(SetTraceIsWidgetAuth, void(const bool isWidgetAuth));
};

class MockContext final : public Context {
public:
    MOCK_METHOD0(Start, bool());
    MOCK_METHOD0(Stop, bool());
    MOCK_CONST_METHOD0(GetContextId, uint64_t());
    MOCK_CONST_METHOD0(GetContextType, ContextType());
    MOCK_CONST_METHOD1(GetScheduleNode, std::shared_ptr<ScheduleNode>(uint64_t scheduleId));
    MOCK_CONST_METHOD0(GetScheduleNodes, std::vector<std::shared_ptr<ScheduleNode>> ());
    MOCK_CONST_METHOD0(GetLatestError, int32_t());
    MOCK_CONST_METHOD0(GetTokenId, uint32_t());
    MOCK_CONST_METHOD0(GetUserId, int32_t());
    MOCK_CONST_METHOD0(GetAuthType, int32_t());
    MOCK_CONST_METHOD0(GetCallerName, std::string());
    MOCK_METHOD2(SetRemoteAuthParam, void(const WidgetParamInner &widgetParam,
	    const sptr<IModalCallback> &modalCallback));

    static std::shared_ptr<Context> CreateWithContextId(uint64_t contextId)
    {
        using namespace testing;
        auto context = Common::MakeShared<MockContext>();
        if (context == nullptr) {
            EXPECT_NE(context, nullptr);
            return nullptr;
        };
        EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(contextId));
        return context;
    }

    static std::shared_ptr<Context> CreateContextWithScheduleNode(uint64_t contextId, std::set<uint64_t> scheduleIdList)
    {
        using namespace testing;
        auto context = Common::MakeShared<MockContext>();
        if (context == nullptr) {
            EXPECT_NE(context, nullptr);
            return nullptr;
        };
        EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(contextId));
        EXPECT_CALL(*context, GetScheduleNode(_)).Times(AnyNumber());

        ON_CALL(*context, GetScheduleNode)
            .WillByDefault([scheduleIdList](uint64_t id) -> std::shared_ptr<ScheduleNode> {
                auto iter = scheduleIdList.find(id);
                if (iter != scheduleIdList.end()) {
                    return MockScheduleNode::CreateWithScheduleId(id);
                }
                return nullptr;
            });
        return context;
    }

    static std::shared_ptr<Context> CreateContextWithScheduleNode(
        uint64_t contextId, const std::set<std::shared_ptr<ScheduleNode>> &scheduleIdList)
    {
        using namespace testing;
        auto context = Common::MakeShared<MockContext>();
        if (context == nullptr) {
            EXPECT_NE(context, nullptr);
            return nullptr;
        };
        EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(contextId));
        EXPECT_CALL(*context, GetScheduleNode(_)).Times(AnyNumber());

        ON_CALL(*context, GetScheduleNode)
            .WillByDefault([scheduleIdList](uint64_t id) -> std::shared_ptr<ScheduleNode> {
                for (auto const &node : scheduleIdList) {
                    if (node->GetScheduleId() == id) {
                        return node;
                    }
                }
                return nullptr;
            });
        return context;
    }

protected:
    MOCK_METHOD1(SetLatestError, void(int32_t error));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_CONTEXT_H

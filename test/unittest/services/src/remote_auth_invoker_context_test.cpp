
/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "remote_auth_invoker_context_test.h"

#include "attributes.h"
#include "context_pool.h"
#include "context_callback_impl.h"
#include "simple_auth_context.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "remote_auth_context.h"
#include "remote_auth_invoker_context.h"
#include "remote_iam_callback.h"
#include "context_appstate_observer.h"
#include "auth_widget_helper.h"
#include "remote_auth_service.h"
#include "mock_context.h"
#include "mock_iuser_auth_interface.h"
 
#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_REMOTE_AUTH_INVOKER_CONTEXT
 
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
 
void RemoteAuthInvokerContextTest::SetUpTestCase()
{
}
 
void RemoteAuthInvokerContextTest::TearDownTestCase()
{
}
 
void RemoteAuthInvokerContextTest::SetUp()
{
}
 
void RemoteAuthInvokerContextTest::TearDown()
{
}
 
HWTEST_F(RemoteAuthInvokerContextTest, OnStartTest, TestSize.Level1)
{
    IAM_LOGI("OnStartTest start");
    uint64_t contextId = 100;
    AuthParamInner authParam = {};
    RemoteAuthInvokerContextParam param = {};
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto remoteAuthInvokerContext = Common::MakeShared<RemoteAuthInvokerContext>(
        contextId, authParam, param, contextCallback
    );
    EXPECT_NO_THROW(remoteAuthInvokerContext->OnStart());
    IAM_LOGI("OnStartTest end");
}

HWTEST_F(RemoteAuthInvokerContextTest, OnMessageTest, TestSize.Level1)
{
    IAM_LOGI("OnMessageTest start");
    uint64_t contextId = 100;
    AuthParamInner authParam = {};
    RemoteAuthInvokerContextParam param = {};
    std::string connectionName = "test5";
    std::string collectorNetworkId = "5";
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto remoteAuthInvokerContext = Common::MakeShared<RemoteAuthInvokerContext>(
        contextId, authParam, param, contextCallback
    );
    std::string srcEndPoint = "start";
    auto request = Common::MakeShared<Attributes>();
    auto reply = Common::MakeShared<Attributes>();
    request->SetInt32Value(Attributes::ATTR_MSG_TYPE, SEND_REMOTE_AUTH_TIP);
    EXPECT_NO_THROW(remoteAuthInvokerContext->OnMessage(connectionName, srcEndPoint, request, reply));
    request->SetInt32Value(Attributes::ATTR_MSG_TYPE, SEND_REMOTE_AUTH_RESULT);
    EXPECT_NO_THROW(remoteAuthInvokerContext->OnMessage(connectionName, srcEndPoint, request, reply));
    request->SetInt32Value(Attributes::ATTR_MSG_TYPE, START_REMOTE_AUTH);
    std::optional<uint32_t> cancelTimerId = 10;
    remoteAuthInvokerContext->cancelTimerId_ = cancelTimerId;
    EXPECT_NO_THROW(remoteAuthInvokerContext->OnMessage(connectionName, srcEndPoint, request, reply));
    IAM_LOGI("OnMessageTest end");
}

HWTEST_F(RemoteAuthInvokerContextTest, OnConnectStatusTest, TestSize.Level1)
{
    IAM_LOGI("OnConnectStatusTest start");
    uint64_t contextId = 100;
    AuthParamInner authParam = {};
    RemoteAuthInvokerContextParam param = {};
    std::string connectionName = "test6";
    std::string collectorNetworkId = "6";
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto remoteAuthInvokerContext = Common::MakeShared<RemoteAuthInvokerContext>(
        contextId, authParam, param, contextCallback
    );
    EXPECT_NO_THROW(remoteAuthInvokerContext->OnConnectStatus(connectionName, ConnectStatus::DISCONNECTED));
    EXPECT_NO_THROW(remoteAuthInvokerContext->OnConnectStatus(connectionName, ConnectStatus::CONNECTED));
    IAM_LOGI("OnConnectStatusTest end");
}

HWTEST_F(RemoteAuthInvokerContextTest, ProcAuthResultMsgInnerTest, TestSize.Level1)
{
    IAM_LOGI("ProcAuthResultMsgInner start");
    uint64_t contextId = 100;
    AuthParamInner authParam = {};
    RemoteAuthInvokerContextParam param = {};
    std::string connectionName = "test7";
    std::string collectorNetworkId = "7";
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto remoteAuthInvokerContext = Common::MakeShared<RemoteAuthInvokerContext>(
        contextId, authParam, param, contextCallback
    );
    auto message = Common::MakeShared<Attributes>();
    message->SetInt32Value(Attributes::ATTR_RESULT, ResultCode::GENERAL_ERROR);
    message->SetInt32Value(Attributes::ATTR_SIGNED_AUTH_RESULT, true);
    int32_t resultCode;
    Attributes attr;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAuthResultFromMessage(_, _, _))
        .WillOnce([](const std::string &remoteUdid, const std::vector<uint8_t> &message,
            HdiAuthResultInfo &authResultInfo) {
                authResultInfo.result = ResultCode::FAIL;
                return 0;
            })
        .WillOnce([](const std::string &remoteUdid, const std::vector<uint8_t> &message,
            HdiAuthResultInfo &authResultInfo) {
                authResultInfo.result = ResultCode::LOCKED;
                return 0;
            })
        .WillRepeatedly([](const std::string &remoteUdid, const std::vector<uint8_t> &message,
            HdiAuthResultInfo &authResultInfo) {
                authResultInfo.result = ResultCode::SUCCESS;
                return 0;
            });
    EXPECT_NO_THROW(remoteAuthInvokerContext->ProcAuthResultMsgInner(*message, resultCode, attr));
    EXPECT_NO_THROW(remoteAuthInvokerContext->ProcAuthResultMsgInner(*message, resultCode, attr));
    EXPECT_NO_THROW(remoteAuthInvokerContext->ProcAuthResultMsgInner(*message, resultCode, attr));
    IAM_LOGI("ProcAuthResultMsgInner end");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
 
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

#include "remote_auth_context_test.h"

#include "attributes.h"
#include "context_pool.h"
#include "context_callback_impl.h"
#include "simple_auth_context.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "remote_auth_context.h"
#include "remote_auth_invoker_context.h"
#include "remote_connect_listener_manager.h"
#include "remote_iam_callback.h"
#include "context_appstate_observer.h"
#include "auth_widget_helper.h"
#include "remote_auth_service.h"
#include "mock_context.h"
 
#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_REMOTE_AUTH_CONTEXT
 
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void RemoteAuthContextTest::SetUpTestCase()
{
}
 
void RemoteAuthContextTest::TearDownTestCase()
{
}
 
void RemoteAuthContextTest::SetUp()
{
}
 
void RemoteAuthContextTest::TearDown()
{
}
 
HWTEST_F(RemoteAuthContextTest, RemoteAuthContextTest, TestSize.Level0)
{
    IAM_LOGI("RemoteAuthContextTest start");
    uint64_t contextId = 100;
    std::shared_ptr<Authentication> auth;
    RemoteAuthContextParam param;
    param.authType = ALL;
    std::string connectionName = "test";
    std::string collectorNetworkId = "1";
    param.connectionName = connectionName;
    param.collectorNetworkId = collectorNetworkId;
    param.executorInfoMsg = {};
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto remoteAuthContext1 = Common::MakeShared<RemoteAuthContext>(
        contextId, auth, param, contextCallback
    );
    EXPECT_NE(remoteAuthContext1, nullptr);
    std::vector<uint8_t> executorInfoMsg = {7, 8, 9};
    param.executorInfoMsg = executorInfoMsg;
    auto remoteAuthContext2 = Common::MakeShared<RemoteAuthContext>(
        contextId, auth, param, contextCallback
    );
    EXPECT_NE(remoteAuthContext2, nullptr);
    bool needSetupConnection = true;
    std::optional<uint32_t> cancelTimerId = 10;
    remoteAuthContext2->cancelTimerId_ = cancelTimerId;
    remoteAuthContext2->needSetupConnection_ = needSetupConnection;
    auto remoteAuthContext3 = Common::MakeShared<RemoteAuthContext>(
        contextId, auth, param, contextCallback
    );
    std::vector<uint8_t> msg = {};
    remoteAuthContext3->SetExecutorInfoMsg(msg);
    remoteAuthContext3->OnTimeOut();
    remoteAuthContext3->OnConnectStatus(connectionName, ConnectStatus::DISCONNECTED);
    IAM_LOGI("RemoteAuthContextTest end");
}

HWTEST_F(RemoteAuthContextTest, OnStartTest, TestSize.Level0)
{
    IAM_LOGI("OnStartTest start");
    uint64_t contextId = 100;
    std::shared_ptr<Authentication> auth;
    RemoteAuthContextParam param;
    param.authType = ALL;
    std::string connectionName = "test2";
    std::string collectorNetworkId = "2";
    param.connectionName = connectionName;
    param.collectorNetworkId = collectorNetworkId;
    param.executorInfoMsg = {};
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    std::vector<uint8_t> executorInfoMsg = {7, 8, 9};
    param.executorInfoMsg = executorInfoMsg;
    auto remoteAuthContext = Common::MakeShared<RemoteAuthContext>(
        contextId, auth, param, contextCallback
    );
    EXPECT_NE(remoteAuthContext, nullptr);
    bool result = remoteAuthContext->OnStart();
    EXPECT_EQ(result, false);
    bool needSetupConnection = true;
    std::optional<uint32_t> cancelTimerId = 10;
    remoteAuthContext->cancelTimerId_ = cancelTimerId;
    remoteAuthContext->needSetupConnection_ = needSetupConnection;
    result = remoteAuthContext->OnStart();
    EXPECT_EQ(result, true);
    IAM_LOGI("OnStartTest end");
}

HWTEST_F(RemoteAuthContextTest, StartAuthDelayedTest, TestSize.Level1)
{
    IAM_LOGI("StartAuthDelayedTest start");
    uint64_t contextId = 100;
    std::shared_ptr<Authentication> auth;
    RemoteAuthContextParam param;
    param.authType = ALL;
    std::string connectionName = "test3";
    std::string collectorNetworkId = "3";
    param.connectionName = connectionName;
    param.collectorNetworkId = collectorNetworkId;
    param.executorInfoMsg = {};
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    std::vector<uint8_t> executorInfoMsg = {6, 8, 9};
    param.executorInfoMsg = executorInfoMsg;
    auto remoteAuthContext = Common::MakeShared<RemoteAuthContext>(
        contextId, auth, param, contextCallback
    );
    EXPECT_NE(remoteAuthContext, nullptr);
    bool needSetupConnection = true;
    remoteAuthContext->needSetupConnection_ = needSetupConnection;
    remoteAuthContext->OnStart();
    EXPECT_NO_THROW(remoteAuthContext->StartAuthDelayed());
    IAM_LOGI("StartAuthDelayedTest end");
}

HWTEST_F(RemoteAuthContextTest, SendQueryExecutorInfoMsgTest, TestSize.Level2)
{
    IAM_LOGI("SendQueryExecutorInfoMsgTest start");
    uint64_t contextId = 100;
    std::shared_ptr<Authentication> auth;
    RemoteAuthContextParam param;
    param.authType = ALL;
    std::string connectionName = "test4";
    std::string collectorNetworkId = "4";
    param.connectionName = connectionName;
    param.collectorNetworkId = collectorNetworkId;
    param.executorInfoMsg = {};
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    std::vector<uint8_t> executorInfoMsg = {6, 8, 7};
    param.executorInfoMsg = executorInfoMsg;
    auto remoteAuthContext = Common::MakeShared<RemoteAuthContext>(
        contextId, auth, param, contextCallback
    );
    EXPECT_NE(remoteAuthContext, nullptr);
    bool needSetupConnection = true;
    remoteAuthContext->needSetupConnection_ = needSetupConnection;
    bool result = remoteAuthContext->SendQueryExecutorInfoMsg();
    EXPECT_EQ(result, false);
    IAM_LOGI("SendQueryExecutorInfoMsgTest end");
}

HWTEST_F(RemoteAuthContextTest, OnConnectStatusTest, TestSize.Level0)
{
    IAM_LOGI("OnConnectStatusTest start");
    uint64_t contextId = 100;
    std::shared_ptr<Authentication> auth;
    RemoteAuthContextParam param;
    param.authType = ALL;
    std::string connectionName = "test5";
    std::string collectorNetworkId = "5";
    param.connectionName = connectionName;
    param.collectorNetworkId = collectorNetworkId;
    param.executorInfoMsg = {};
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    std::vector<uint8_t> executorInfoMsg = {6, 5, 7};
    param.executorInfoMsg = executorInfoMsg;
    auto remoteAuthContext = Common::MakeShared<RemoteAuthContext>(
        contextId, auth, param, contextCallback
    );
    EXPECT_NO_THROW(remoteAuthContext->OnConnectStatus(connectionName, ConnectStatus::DISCONNECTED));
    EXPECT_NO_THROW(remoteAuthContext->OnConnectStatus(connectionName, ConnectStatus::CONNECTED));
    IAM_LOGI("OnConnectStatusTest end");
}

HWTEST_F(RemoteAuthContextTest, SetupConnectionTest01, TestSize.Level0)
{
    IAM_LOGI("SetupConnectionTest01 start");
    uint64_t contextId = 100;
    std::shared_ptr<Authentication> auth;
    RemoteAuthContextParam param;
    param.authType = ALL;
    std::string connectionName = "test6";
    std::string collectorNetworkId = "6";
    param.connectionName = connectionName;
    param.collectorNetworkId = collectorNetworkId;
    param.executorInfoMsg = {};
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    std::vector<uint8_t> executorInfoMsg = {6, 7, 8};
    param.executorInfoMsg = executorInfoMsg;
    auto remoteAuthContext = Common::MakeShared<RemoteAuthContext>(
        contextId, auth, param, contextCallback
    );
    EXPECT_NO_THROW(remoteAuthContext->SetupConnection());
    EXPECT_NO_THROW(remoteAuthContext->SetupConnection());
    std::string endPointName = "RemoteAuthContext";
    RemoteConnectListenerManager::GetInstance().FindListener(connectionName, endPointName);
    RemoteConnectListenerManager::GetInstance().OnConnectionUp(connectionName);
    RemoteConnectListenerManager::GetInstance().OnConnectionDown(connectionName);
    connectionName = "test555";
    RemoteConnectListenerManager::GetInstance().OnConnectionUp(connectionName);
    RemoteConnectListenerManager::GetInstance().OnConnectionDown(connectionName);
    IAM_LOGI("SetupConnectionTest01 end");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
 
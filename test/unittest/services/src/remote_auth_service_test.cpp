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

#include "remote_auth_service_test.h"

#include <string>

#include "attributes.h"
#include "context_pool.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "mock_ipc_common.h"
#include "remote_auth_service.h"
#include "remote_msg_util.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_REMOTE_AUTH_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void RemoteAuthServiceTest::SetUpTestCase()
{
}

void RemoteAuthServiceTest::TearDownTestCase()
{
}

void RemoteAuthServiceTest::SetUp()
{
    IpcCommon::SetSkipActiveUserIdCallerFlag(false);
}

void RemoteAuthServiceTest::TearDown()
{
    IpcCommon::SetSkipActiveUserIdCallerFlag(false);
}

HWTEST_F(RemoteAuthServiceTest, ProcStartRemoteAuthRequest_InvalidUserId_FallbackSuccess, TestSize.Level0)
{
    IAM_LOGI("ProcStartRemoteAuthRequest_InvalidUserId_FallbackSuccess start");
    
    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    std::shared_ptr<Attributes> reply = Common::MakeShared<Attributes>();
    
    AuthParamInner authParam = {};
    authParam.userId = INVALID_USER_ID;
    authParam.authType = PIN;
    authParam.authTrustLevel = ATL1;
    authParam.challenge = {1, 2, 3};
    
    bool encodeRet = RemoteMsgUtil::EncodeAuthParam(authParam, *request);
    EXPECT_TRUE(encodeRet);
    
    bool setCollectorRet = request->SetStringValue(Attributes::ATTR_COLLECTOR_NETWORK_ID, "collector_network_id");
    EXPECT_TRUE(setCollectorRet);
    
    bool setTokenIdRet = request->SetUint32Value(Attributes::ATTR_COLLECTOR_TOKEN_ID, 12345);
    EXPECT_TRUE(setTokenIdRet);
    
    bool setCallerNameRet = request->SetStringValue(Attributes::ATTR_CALLER_NAME, "test_caller");
    EXPECT_TRUE(setCallerNameRet);
    
    bool setCallerTypeRet = request->SetInt32Value(Attributes::ATTR_CALLER_TYPE, 0);
    EXPECT_TRUE(setCallerTypeRet);
    
    auto &service = RemoteAuthService::GetInstance();
    int32_t result = service.ProcStartRemoteAuthRequest("connection_name", request, reply);
    
    EXPECT_EQ(result, SUCCESS);
    
    uint64_t contextId = 0;
    bool getContextIdRet = reply->GetUint64Value(Attributes::ATTR_CONTEXT_ID, contextId);
    EXPECT_TRUE(getContextIdRet);
    EXPECT_NE(contextId, 0U);
    
    IAM_LOGI("ProcStartRemoteAuthRequest_InvalidUserId_FallbackSuccess end");
}

HWTEST_F(RemoteAuthServiceTest, ProcStartRemoteAuthRequest_InvalidUserId_GetActiveUserIdFails, TestSize.Level0)
{
    IAM_LOGI("ProcStartRemoteAuthRequest_InvalidUserId_GetActiveUserIdFails start");
    
    IpcCommon::SetSkipActiveUserIdCallerFlag(true);
    
    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    std::shared_ptr<Attributes> reply = Common::MakeShared<Attributes>();
    
    AuthParamInner authParam = {};
    authParam.userId = INVALID_USER_ID;
    authParam.authType = PIN;
    authParam.authTrustLevel = ATL1;
    authParam.challenge = {1, 2, 3};
    
    bool encodeRet = RemoteMsgUtil::EncodeAuthParam(authParam, *request);
    EXPECT_TRUE(encodeRet);
    
    bool setCollectorRet = request->SetStringValue(Attributes::ATTR_COLLECTOR_NETWORK_ID, "collector_network_id");
    EXPECT_TRUE(setCollectorRet);
    
    bool setTokenIdRet = request->SetUint32Value(Attributes::ATTR_COLLECTOR_TOKEN_ID, 12345);
    EXPECT_TRUE(setTokenIdRet);
    
    bool setCallerNameRet = request->SetStringValue(Attributes::ATTR_CALLER_NAME, "test_caller");
    EXPECT_TRUE(setCallerNameRet);
    
    bool setCallerTypeRet = request->SetInt32Value(Attributes::ATTR_CALLER_TYPE, 0);
    EXPECT_TRUE(setCallerTypeRet);
    
    auto &service = RemoteAuthService::GetInstance();
    int32_t result = service.ProcStartRemoteAuthRequest("connection_name", request, reply);
    
    EXPECT_EQ(result, GENERAL_ERROR);
    
    IAM_LOGI("ProcStartRemoteAuthRequest_InvalidUserId_GetActiveUserIdFails end");
}

HWTEST_F(RemoteAuthServiceTest, ProcStartRemoteAuthRequest_ValidUserId, TestSize.Level0)
{
    IAM_LOGI("ProcStartRemoteAuthRequest_ValidUserId start");
    
    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    std::shared_ptr<Attributes> reply = Common::MakeShared<Attributes>();
    
    AuthParamInner authParam = {};
    authParam.userId = 100;
    authParam.authType = PIN;
    authParam.authTrustLevel = ATL1;
    authParam.challenge = {1, 2, 3};
    
    bool encodeRet = RemoteMsgUtil::EncodeAuthParam(authParam, *request);
    EXPECT_TRUE(encodeRet);
    
    bool setCollectorRet = request->SetStringValue(Attributes::ATTR_COLLECTOR_NETWORK_ID, "collector_network_id");
    EXPECT_TRUE(setCollectorRet);
    
    bool setTokenIdRet = request->SetUint32Value(Attributes::ATTR_COLLECTOR_TOKEN_ID, 12345);
    EXPECT_TRUE(setTokenIdRet);
    
    bool setCallerNameRet = request->SetStringValue(Attributes::ATTR_CALLER_NAME, "test_caller");
    EXPECT_TRUE(setCallerNameRet);
    
    bool setCallerTypeRet = request->SetInt32Value(Attributes::ATTR_CALLER_TYPE, 0);
    EXPECT_TRUE(setCallerTypeRet);
    
    auto &service = RemoteAuthService::GetInstance();
    int32_t result = service.ProcStartRemoteAuthRequest("connection_name", request, reply);
    
    EXPECT_EQ(result, SUCCESS);
    
    uint64_t contextId = 0;
    bool getContextIdRet = reply->GetUint64Value(Attributes::ATTR_CONTEXT_ID, contextId);
    EXPECT_TRUE(getContextIdRet);
    EXPECT_NE(contextId, 0U);
    
    IAM_LOGI("ProcStartRemoteAuthRequest_ValidUserId end");
}

HWTEST_F(RemoteAuthServiceTest, ProcStartRemoteAuthRequest_DecodeAuthParamFails, TestSize.Level0)
{
    IAM_LOGI("ProcStartRemoteAuthRequest_DecodeAuthParamFails start");
    
    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    std::shared_ptr<Attributes> reply = Common::MakeShared<Attributes>();
    
    auto &service = RemoteAuthService::GetInstance();
    int32_t result = service.ProcStartRemoteAuthRequest("connection_name", request, reply);
    
    EXPECT_EQ(result, GENERAL_ERROR);
    
    IAM_LOGI("ProcStartRemoteAuthRequest_DecodeAuthParamFails end");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

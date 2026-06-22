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

#include "remote_msg_util_test.h"

#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>

#include "remote_msg_util.h"
#include "device_manager.h"
#include "device_manager_util.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "parameter.h"
#include "resource_node_pool.h"

#include "mock_resource_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void RemoteMsgUtilTest::SetUpTestCase()
{
}

void RemoteMsgUtilTest::TearDownTestCase()
{
}

void RemoteMsgUtilTest::SetUp()
{
}

void RemoteMsgUtilTest::TearDown()
{
}

HWTEST_F(RemoteMsgUtilTest, GetConnectionNameTest, TestSize.Level0)
{
    uint64_t contextId = 0;
    std::string connectionName = "";
    EXPECT_FALSE(RemoteMsgUtil::GetConnectionName(contextId, connectionName));
}

HWTEST_F(RemoteMsgUtilTest, EncodeQueryExecutorInfoReplyTest, TestSize.Level0)
{
    std::vector<ExecutorInfo> executorInfoArray(1);
    std::vector<uint8_t> signedRemoteExecutorInfo;
    Attributes attr = {};

    EXPECT_TRUE(RemoteMsgUtil::EncodeQueryExecutorInfoReply(executorInfoArray, signedRemoteExecutorInfo, attr));
}

HWTEST_F(RemoteMsgUtilTest, DecodeQueryExecutorInfoReplyTest, TestSize.Level0)
{
    std::vector<ExecutorInfo> executorInfoArray(1);
    Attributes attr = {};

    EXPECT_FALSE(RemoteMsgUtil::DecodeQueryExecutorInfoReply(attr, executorInfoArray));
}

HWTEST_F(RemoteMsgUtilTest, SetAndGetExecutorInfoToAttributesTest, TestSize.Level0)
{
    ExecutorInfo executorInfo = {};
    Attributes attr = {};
    std::vector<uint8_t> signedRemoteExecutorInfo;

    EXPECT_TRUE(RemoteMsgUtil::SetExecutorInfoToAttributes(executorInfo, attr));
    EXPECT_TRUE(RemoteMsgUtil::GetExecutorInfoFromAttributes(attr, signedRemoteExecutorInfo, executorInfo));
}

HWTEST_F(RemoteMsgUtilTest, SetExecutorInfoArrayToAttributesTest, TestSize.Level0)
{
    std::vector<ExecutorInfo> executorInfoArray(1);
    Attributes attr = {};

    EXPECT_TRUE(RemoteMsgUtil::SetExecutorInfoArrayToAttributes(executorInfoArray, attr));
}

HWTEST_F(RemoteMsgUtilTest, GetExecutorInfoArrayFromAttributesTest, TestSize.Level0)
{
    Attributes attr = {};
    std::vector<uint8_t> signedRemoteExecutorInfo;
    std::vector<ExecutorInfo> executorInfoArray(1);

    Attributes temp = {};
    std::vector<ExecutorInfo> executorInfoArrayTmp;
    ExecutorInfo executorInfo = {};
    executorInfoArrayTmp.emplace_back(executorInfo);
    RemoteMsgUtil::SetExecutorInfoArrayToAttributes(executorInfoArrayTmp, temp);

    EXPECT_FALSE(RemoteMsgUtil::GetExecutorInfoArrayFromAttributes(attr, signedRemoteExecutorInfo, executorInfoArray));
}

HWTEST_F(RemoteMsgUtilTest, GetQueryExecutorInfoReplyTest_001, TestSize.Level0)
{
    std::vector<int32_t> authTypes(1);
    int32_t executorRole = 0;
    std::string remoteUdid = "";
    Attributes attr = {};

    const uint64_t EXECUTOR_INDEX = 100;
    auto resource = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX);
    ResourceNodePool::Instance().Insert(resource);

    EXPECT_EQ(RemoteMsgUtil::GetQueryExecutorInfoReply(authTypes, executorRole, remoteUdid, attr),
        ResultCode::GENERAL_ERROR);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(RemoteMsgUtilTest, GetQueryExecutorInfoReplyTest_002, TestSize.Level0)
{
    std::vector<int32_t> authTypes(1);
    int32_t executorRole = COLLECTOR;
    std::string remoteUdid = "";
    Attributes attr = {};

    const uint64_t EXECUTOR_INDEX = 100;
    auto resource = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX);
    ResourceNodePool::Instance().Insert(resource);

    EXPECT_NE(
        RemoteMsgUtil::GetQueryExecutorInfoReply(authTypes, executorRole, remoteUdid, attr), ResultCode::SUCCESS);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(RemoteMsgUtilTest, GetQueryExecutorInfoReplyTest_003, TestSize.Level0)
{
    std::vector<int32_t> authTypes(1, PIN);
    int32_t executorRole = COLLECTOR;
    std::string remoteUdid = "";
    Attributes attr = {};

    const uint64_t EXECUTOR_INDEX = 100;
    auto resource = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX);
    ResourceNodePool::Instance().Insert(resource);

    EXPECT_NE(
        RemoteMsgUtil::GetQueryExecutorInfoReply(authTypes, executorRole, remoteUdid, attr), ResultCode::SUCCESS);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(RemoteMsgUtilTest, EncodeAndDecodeAuthParamTest, TestSize.Level0)
{
    AuthParamInner authParam = {};
    Attributes attr = {};

    EXPECT_TRUE(RemoteMsgUtil::EncodeAuthParam(authParam, attr));
    EXPECT_TRUE(RemoteMsgUtil::DecodeAuthParam(attr, authParam));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

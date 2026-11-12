/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "co_auth_service_test.h"

#include <future>

#include "co_auth_service.h"
#include "iam_ptr.h"
#include "mock_executor_callback.h"
#include "mock_ipc_common.h"
#include "hdi_type_aliases.h"
#include "mock_iuser_auth_interface.h"
#include "mock_resource_node.h"
#include "resource_node_pool.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void CoAuthServiceTest::SetUpTestCase()
{
}

void CoAuthServiceTest::TearDownTestCase()
{
}

void CoAuthServiceTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void CoAuthServiceTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTest001, TestSize.Level0)
{
    sptr<MockExecutorCallback> testCallback(new (std::nothrow) MockExecutorCallback());
    EXPECT_NE(testCallback, nullptr);

    IpcExecutorRegisterInfo info = {};
    info.authType = static_cast<int32_t>(FINGERPRINT);
    info.executorRole = static_cast<int32_t>(SCHEDULER);
    info.executorSensorHint = 0;
    info.executorMatcher = 0;
    info.esl = static_cast<int32_t>(ESL1);
    info.publicKey = {'a', 'b', 'c', 'd'};
    
    auto service = Common::MakeShared<CoAuthService>();
    EXPECT_NE(service, nullptr);
    service->SetIsReady(true);
    service->SetAccessTokenReady(true);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    std::promise<void> promise;
    EXPECT_CALL(*testCallback, OnMessengerReady(_, _, _)).Times(1).WillOnce(
        [&promise](const sptr<IExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList) {
            promise.set_value();
            return SUCCESS;
        }
    );
    EXPECT_CALL(*mockHdi, AddExecutor(_, _, _, _))
        .Times(2)
        .WillOnce(Return(HDF_FAILURE))
        .WillOnce(
            [](const HdiExecutorRegisterInfo &info, uint64_t &index, std::vector<uint8_t> &publicKey,
                std::vector<uint64_t> &templateIds) {
                index = 12345;
                return HDF_SUCCESS;
            }
        );
    IpcCommon::AddPermission(ACCESS_AUTH_RESPOOL);
    sptr<IExecutorCallback> callbackInterface = testCallback;
    uint64_t executorIndex = 0;
    EXPECT_EQ(service->ExecutorRegister(info, callbackInterface, executorIndex), GENERAL_ERROR);
    EXPECT_EQ(executorIndex, 0);
    EXPECT_EQ(service->ExecutorRegister(info, callbackInterface, executorIndex), SUCCESS);
    EXPECT_NE(executorIndex, 0);
    promise.get_future().get();
    EXPECT_EQ(service->ExecutorUnregister(executorIndex), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTest002, TestSize.Level0)
{
    auto service = Common::MakeShared<CoAuthService>();
    EXPECT_NE(service, nullptr);

    IpcExecutorRegisterInfo info = {};
    sptr<IExecutorCallback> testCallback(nullptr);
    uint64_t executorIndex = 0;
    EXPECT_EQ(service->ExecutorRegister(info, testCallback, executorIndex), INVALID_PARAMETERS);
    EXPECT_EQ(executorIndex, 0);
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTestExecutorRegister001, TestSize.Level0)
{
    sptr<MockExecutorCallback> testCallback(new (std::nothrow) MockExecutorCallback());
    EXPECT_NE(testCallback, nullptr);

    IpcExecutorRegisterInfo info = {};
    info.authType = static_cast<int32_t>(FINGERPRINT);
    info.executorRole = static_cast<int32_t>(SCHEDULER);
    info.executorSensorHint = 0;
    info.executorMatcher = 0;
    info.esl = static_cast<int32_t>(ESL1);
    info.publicKey = {'a', 'b', 'c', 'd'};
    
    auto service = Common::MakeShared<CoAuthService>();
    EXPECT_NE(service, nullptr);
    service->SetIsReady(false);
    service->SetAccessTokenReady(false);
    sptr<IExecutorCallback> callbackInterface = testCallback;
    uint64_t executorIndex = 0;
    EXPECT_EQ(service->ExecutorRegister(info, callbackInterface, executorIndex), GENERAL_ERROR);
    EXPECT_EQ(executorIndex, INVALID_EXECUTOR_INDEX);
    EXPECT_EQ(service->ExecutorUnregister(executorIndex), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTestExecutorRegister002, TestSize.Level0)
{
    sptr<MockExecutorCallback> testCallback(new (std::nothrow) MockExecutorCallback());
    EXPECT_NE(testCallback, nullptr);

    IpcExecutorRegisterInfo info = {};
    info.authType = static_cast<int32_t>(FINGERPRINT);
    info.executorRole = static_cast<int32_t>(SCHEDULER);
    info.executorSensorHint = 0;
    info.executorMatcher = 0;
    info.esl = static_cast<int32_t>(ESL1);
    info.publicKey = {'a', 'b', 'c', 'd'};
    
    auto service = Common::MakeShared<CoAuthService>();
    EXPECT_NE(service, nullptr);
    service->SetIsReady(true);
    service->SetAccessTokenReady(true);
    sptr<IExecutorCallback> callbackInterface = testCallback;
    uint64_t executorIndex = 0;
    EXPECT_EQ(service->ExecutorRegister(info, callbackInterface, executorIndex), CHECK_PERMISSION_FAILED);
    EXPECT_EQ(executorIndex, INVALID_EXECUTOR_INDEX);
    EXPECT_EQ(service->ExecutorUnregister(executorIndex), CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTestDump, TestSize.Level0)
{
    int testFd1 = -1;
    int testFd2 = 1;
    std::vector<std::u16string> testArgs;

    auto service = Common::MakeShared<CoAuthService>();
    EXPECT_NE(service, nullptr);

    auto node = MockResourceNode::CreateWithExecuteIndex(20);
    EXPECT_NE(node, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(node));

    EXPECT_EQ(service->Dump(testFd1, testArgs), INVALID_PARAMETERS);
    EXPECT_EQ(service->Dump(testFd2, testArgs), SUCCESS);
    testArgs.push_back(u"-h");
    EXPECT_EQ(service->Dump(testFd2, testArgs), SUCCESS);
    testArgs.clear();
    testArgs.push_back(u"-l");
    EXPECT_EQ(service->Dump(testFd2, testArgs), SUCCESS);
    testArgs.clear();
    testArgs.push_back(u"-k");
    EXPECT_EQ(service->Dump(testFd2, testArgs), GENERAL_ERROR);

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(20));
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTestRegisterAccessTokenListener, TestSize.Level0)
{
    auto service = Common::MakeShared<CoAuthService>();
    EXPECT_NE(service, nullptr);
    service->OnEngineReady();
    service->SetIsReady(true);
    service->SetAccessTokenReady(true);
    EXPECT_EQ(service->RegisterAccessTokenListener(), SUCCESS);
    EXPECT_EQ(service->RegisterAccessTokenListener(), SUCCESS);
    EXPECT_EQ(service->UnRegisterAccessTokenListener(), SUCCESS);
    EXPECT_EQ(service->UnRegisterAccessTokenListener(), SUCCESS);
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTestNotifyFwkReady, TestSize.Level0)
{
    auto service = Common::MakeShared<CoAuthService>();
    EXPECT_NE(service, nullptr);
    service->SetIsReady(false);
    EXPECT_NO_THROW(service->NotifyFwkReady());
    service->SetIsReady(true);
    EXPECT_NO_THROW(service->NotifyFwkReady());
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTestOnEngineUnavailable, TestSize.Level0)
{
    auto service = Common::MakeShared<CoAuthService>();
    EXPECT_NE(service, nullptr);
    service->SetIsReady(true);
    EXPECT_NO_THROW(service->OnEngineReady());
    EXPECT_NO_THROW(service->OnEngineUnavailable());
    EXPECT_NO_THROW(service->OnEngineUnavailable());
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTestIsFwkReady, TestSize.Level0)
{
    auto service = Common::MakeShared<CoAuthService>();
    EXPECT_NE(service, nullptr);
    service->SetIsReady(true);
    service->SetAccessTokenReady(true);
    EXPECT_NO_THROW(service->NotifyFwkReady());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
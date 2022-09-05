/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "co_auth_service.h"
#include "iam_ptr.h"
#include "mock_executor_callback.h"
#include "mock_iuser_auth_interface.h"
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

HWTEST_F(CoAuthServiceTest, CoAuthServiceTestExecutorRegister, TestSize.Level0)
{
    sptr<ExecutorCallbackInterface> testCallback = new MockExecutorCallback();
    EXPECT_NE(testCallback, nullptr);
    sptr<MockExecutorCallback> tempCallback = static_cast<MockExecutorCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);

    CoAuthInterface::ExecutorRegisterInfo info = {};
    info.authType = FINGERPRINT;
    info.executorRole = SCHEDULER;
    info.executorSensorHint = 0;
    info.executorMatcher = 0;
    info.esl = ESL1;
    info.publicKey = {'a', 'b', 'c', 'd'};
    
    auto service = Common::MakeShared<CoAuthService>(1, true);
    EXPECT_NE(service, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnMessengerReady(_, _, _)).Times(1);
    EXPECT_CALL(*mockHdi, AddExecutor(_, _, _, _)).Times(1);
    EXPECT_CALL(*mockHdi, DeleteExecutor(_)).Times(1);
    uint64_t executorIndex = service->ExecutorRegister(info, testCallback);
    EXPECT_EQ(executorIndex, 0);
    EXPECT_EQ(ResourceNodePool::Instance().Delete(executorIndex), true);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
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

#include "remote_auth_callback_service_test.h"

#include "remote_auth_callback_service.h"
#include "iam_ptr.h"
#include "mock_remote_auth_client_callback.h"
#include "mock_set_widget_param_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void RemoteAuthCallbackServiceTest::SetUpTestCase()
{
}

void RemoteAuthCallbackServiceTest::TearDownTestCase()
{
}

void RemoteAuthCallbackServiceTest::SetUp()
{
}

void RemoteAuthCallbackServiceTest::TearDown()
{
}

HWTEST_F(RemoteAuthCallbackServiceTest, RemoteAuthCallbackServiceTest001, TestSize.Level0)
{
    std::shared_ptr<RemoteAuthClientCallback> testCallback = nullptr;
    auto service = Common::MakeShared<RemoteAuthCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);

    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    sptr<ISetWidgetParamCallback> testSetWidgetParamCallback = nullptr;
    int32_t result = service->OnGetRemoteAuthWidgetParam(testChallenge, testSetWidgetParamCallback);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(RemoteAuthCallbackServiceTest, RemoteAuthCallbackServiceTest002, TestSize.Level0)
{
    std::shared_ptr<RemoteAuthClientCallback> testCallback = nullptr;
    auto service = Common::MakeShared<RemoteAuthCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);

    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    int32_t testResultCode = SUCCESS;
    std::vector<uint8_t> testExtraInfo = {5, 6, 7, 8};
    int32_t result = service->OnRemoteAuthResult(testChallenge, testResultCode, testExtraInfo);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(RemoteAuthCallbackServiceTest, RemoteAuthCallbackServiceTest003, TestSize.Level0)
{
    auto testCallback = Common::MakeShared<MockRemoteAuthClientCallback>();
    EXPECT_NE(testCallback, nullptr);

    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    sptr<ISetWidgetParamCallback> testSetWidgetParamCallback = nullptr;

    EXPECT_CALL(*testCallback, OnGetRemoteAuthWidgetParam(_, _)).Times(1);
    auto service = Common::MakeShared<RemoteAuthCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    int32_t result = service->OnGetRemoteAuthWidgetParam(testChallenge, testSetWidgetParamCallback);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(RemoteAuthCallbackServiceTest, RemoteAuthCallbackServiceTest004, TestSize.Level0)
{
    auto testCallback = Common::MakeShared<MockRemoteAuthClientCallback>();
    EXPECT_NE(testCallback, nullptr);

    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    int32_t testResultCode = SUCCESS;
    std::vector<uint8_t> testExtraInfo = {5, 6, 7, 8};

    EXPECT_CALL(*testCallback, OnRemoteAuthResult(_, _, _)).Times(1);
    auto service = Common::MakeShared<RemoteAuthCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    int32_t result = service->OnRemoteAuthResult(testChallenge, testResultCode, testExtraInfo);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(RemoteAuthCallbackServiceTest, RemoteAuthCallbackServiceTest005, TestSize.Level0)
{
    auto testCallback = Common::MakeShared<MockRemoteAuthClientCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<RemoteAuthCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);

    uint32_t testCode = 12345;
    int32_t result = service->CallbackEnter(testCode);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(RemoteAuthCallbackServiceTest, RemoteAuthCallbackServiceTest006, TestSize.Level0)
{
    auto testCallback = Common::MakeShared<MockRemoteAuthClientCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<RemoteAuthCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);

    uint32_t testCode = 12345;
    int32_t testResult = 0;
    int32_t result = service->CallbackExit(testCode, testResult);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(RemoteAuthCallbackServiceTest, RemoteAuthCallbackServiceTest007, TestSize.Level0)
{
    auto testCallback = Common::MakeShared<MockRemoteAuthClientCallback>();
    EXPECT_NE(testCallback, nullptr);

    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    int32_t testResultCode = FAIL;
    std::vector<uint8_t> testExtraInfo;

    EXPECT_CALL(*testCallback, OnRemoteAuthResult(_, _, _)).Times(1);
    auto service = Common::MakeShared<RemoteAuthCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    int32_t result = service->OnRemoteAuthResult(testChallenge, testResultCode, testExtraInfo);
    EXPECT_EQ(result, SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

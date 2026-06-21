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

#include "set_widget_param_callback_service_test.h"

#include "set_widget_param_callback_service.h"
#include "iam_ptr.h"
#include "context_pool.h"
#include "mock_context.h"
#include "mock_modal_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void SetWidgetParamCallbackServiceTest::SetUpTestCase()
{
}

void SetWidgetParamCallbackServiceTest::TearDownTestCase()
{
}

void SetWidgetParamCallbackServiceTest::SetUp()
{
}

void SetWidgetParamCallbackServiceTest::TearDown()
{
}

HWTEST_F(SetWidgetParamCallbackServiceTest, SetWidgetParamCallbackServiceTest001, TestSize.Level0)
{
    uint64_t testContextId = 12345;
    auto service = Common::MakeShared<SetWidgetParamCallbackService>(testContextId);
    EXPECT_NE(service, nullptr);

    IpcWidgetParamInner testIpcWidgetParamInner = {};
    testIpcWidgetParamInner.title = "test title";
    testIpcWidgetParamInner.navigationButtonText = "test navigation";
    testIpcWidgetParamInner.windowMode = 0;
    testIpcWidgetParamInner.hasContext = false;
    sptr<IModalCallback> testModalCallback = nullptr;

    int32_t result = service->OnSetRemoteAuthWidgetParam(testIpcWidgetParamInner, testModalCallback);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(SetWidgetParamCallbackServiceTest, SetWidgetParamCallbackServiceTest002, TestSize.Level0)
{
    uint64_t testContextId = 0;
    auto service = Common::MakeShared<SetWidgetParamCallbackService>(testContextId);
    EXPECT_NE(service, nullptr);

    IpcWidgetParamInner testIpcWidgetParamInner = {};
    testIpcWidgetParamInner.title = "test title";
    testIpcWidgetParamInner.navigationButtonText = "test navigation";
    testIpcWidgetParamInner.windowMode = 0;
    testIpcWidgetParamInner.hasContext = false;
    sptr<IModalCallback> testModalCallback = nullptr;

    int32_t result = service->OnSetRemoteAuthWidgetParam(testIpcWidgetParamInner, testModalCallback);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(SetWidgetParamCallbackServiceTest, SetWidgetParamCallbackServiceTest003, TestSize.Level0)
{
    uint64_t testContextId = 12345;
    auto service = Common::MakeShared<SetWidgetParamCallbackService>(testContextId);
    EXPECT_NE(service, nullptr);

    uint32_t testCode = 54321;
    int32_t result = service->CallbackEnter(testCode);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SetWidgetParamCallbackServiceTest, SetWidgetParamCallbackServiceTest004, TestSize.Level0)
{
    uint64_t testContextId = 12345;
    auto service = Common::MakeShared<SetWidgetParamCallbackService>(testContextId);
    EXPECT_NE(service, nullptr);

    uint32_t testCode = 54321;
    int32_t testResult = SUCCESS;
    int32_t result = service->CallbackExit(testCode, testResult);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SetWidgetParamCallbackServiceTest, SetWidgetParamCallbackServiceTest005, TestSize.Level0)
{
    uint64_t testContextId = 12345;
    auto service = Common::MakeShared<SetWidgetParamCallbackService>(testContextId);
    EXPECT_NE(service, nullptr);

    auto mockContext = std::static_pointer_cast<MockContext>(MockContext::CreateWithContextId(testContextId));
    EXPECT_NE(mockContext, nullptr);
    ContextPool::Instance().Insert(mockContext);

    IpcWidgetParamInner testIpcWidgetParamInner = {};
    testIpcWidgetParamInner.title = "test title";
    testIpcWidgetParamInner.navigationButtonText = "test navigation";
    testIpcWidgetParamInner.windowMode = 0;
    testIpcWidgetParamInner.hasContext = false;

    sptr<MockModalCallback> mockModalCallback = new (std::nothrow) MockModalCallback();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_CALL(*mockContext, SetRemoteAuthParam(_, _)).Times(1);
    EXPECT_CALL(*mockContext, Start()).WillOnce(Return(true));

    int32_t result = service->OnSetRemoteAuthWidgetParam(testIpcWidgetParamInner, mockModalCallback);
    EXPECT_EQ(result, SUCCESS);

    ContextPool::Instance().Delete(testContextId);
}

HWTEST_F(SetWidgetParamCallbackServiceTest, SetWidgetParamCallbackServiceTest006, TestSize.Level0)
{
    uint64_t testContextId = 12345;
    auto service = Common::MakeShared<SetWidgetParamCallbackService>(testContextId);
    EXPECT_NE(service, nullptr);

    auto mockContext = std::static_pointer_cast<MockContext>(MockContext::CreateWithContextId(testContextId));
    EXPECT_NE(mockContext, nullptr);
    ContextPool::Instance().Insert(mockContext);

    IpcWidgetParamInner testIpcWidgetParamInner = {};
    testIpcWidgetParamInner.title = "test title";
    testIpcWidgetParamInner.navigationButtonText = "test navigation";
    testIpcWidgetParamInner.windowMode = static_cast<int32_t>(WindowModeType::UNKNOWN_WINDOW_MODE);
    testIpcWidgetParamInner.hasContext = false;

    sptr<MockModalCallback> mockModalCallback = new (std::nothrow) MockModalCallback();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_CALL(*mockContext, SetRemoteAuthParam(_, _)).Times(1);
    EXPECT_CALL(*mockContext, Start()).WillOnce(Return(true));

    int32_t result = service->OnSetRemoteAuthWidgetParam(testIpcWidgetParamInner, mockModalCallback);
    EXPECT_EQ(result, SUCCESS);

    ContextPool::Instance().Delete(testContextId);
}

HWTEST_F(SetWidgetParamCallbackServiceTest, SetWidgetParamCallbackServiceTest007, TestSize.Level0)
{
    uint64_t testContextId = 12345;
    auto service = Common::MakeShared<SetWidgetParamCallbackService>(testContextId);
    EXPECT_NE(service, nullptr);

    auto mockContext = std::static_pointer_cast<MockContext>(MockContext::CreateWithContextId(testContextId));
    EXPECT_NE(mockContext, nullptr);
    ContextPool::Instance().Insert(mockContext);

    IpcWidgetParamInner testIpcWidgetParamInner = {};
    testIpcWidgetParamInner.title = "test title";
    testIpcWidgetParamInner.navigationButtonText = "test navigation";
    testIpcWidgetParamInner.windowMode = static_cast<int32_t>(WindowModeType::DIALOG_BOX);
    testIpcWidgetParamInner.hasContext = true;

    sptr<MockModalCallback> mockModalCallback = new (std::nothrow) MockModalCallback();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_CALL(*mockContext, SetRemoteAuthParam(_, _)).Times(1);
    EXPECT_CALL(*mockContext, Start()).WillOnce(Return(false));

    int32_t result = service->OnSetRemoteAuthWidgetParam(testIpcWidgetParamInner, mockModalCallback);
    EXPECT_EQ(result, GENERAL_ERROR);

    ContextPool::Instance().Delete(testContextId);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

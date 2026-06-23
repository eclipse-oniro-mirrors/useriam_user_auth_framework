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

#include "set_widget_param_callback_test.h"

#include "set_widget_param_callback.h"
#include "iam_ptr.h"
#include "mock_set_widget_param_callback.h"
#include "mock_user_auth_modal_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void SetWidgetParamCallbackTest::SetUpTestCase()
{
}

void SetWidgetParamCallbackTest::TearDownTestCase()
{
}

void SetWidgetParamCallbackTest::SetUp()
{
}

void SetWidgetParamCallbackTest::TearDown()
{
}

HWTEST_F(SetWidgetParamCallbackTest, SetWidgetParamCallbackTest001, TestSize.Level0)
{
    sptr<ISetWidgetParamCallback> testCallback = nullptr;
    auto service = Common::MakeShared<SetWidgetParamClientCallback>(testCallback);
    EXPECT_NE(service, nullptr);

    WidgetParamNapi testWidgetParam = {};
    testWidgetParam.title = "test title";
    testWidgetParam.navigationButtonText = "test navigation";
    testWidgetParam.windowMode = WindowModeType::DIALOG_BOX;
    testWidgetParam.hasContext = false;
    std::shared_ptr<UserAuthModalClientCallback> testModalCallback = nullptr;

    int32_t result = service->OnSetRemoteAuthWidgetParam(testWidgetParam, testModalCallback);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(SetWidgetParamCallbackTest, SetWidgetParamCallbackTest002, TestSize.Level0)
{
    sptr<MockSetWidgetParamCallback> mockCallback = new (std::nothrow) MockSetWidgetParamCallback();
    EXPECT_NE(mockCallback, nullptr);

    auto service = Common::MakeShared<SetWidgetParamClientCallback>(mockCallback);
    EXPECT_NE(service, nullptr);

    WidgetParamNapi testWidgetParam = {};
    testWidgetParam.title = "test title";
    testWidgetParam.navigationButtonText = "test navigation";
    testWidgetParam.windowMode = WindowModeType::DIALOG_BOX;
    testWidgetParam.hasContext = false;
    auto mockModalCallback = Common::MakeShared<MockUserAuthModalCallback>();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_CALL(*mockCallback, OnSetRemoteAuthWidgetParam(_, _)).Times(1);
    int32_t result = service->OnSetRemoteAuthWidgetParam(testWidgetParam, mockModalCallback);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SetWidgetParamCallbackTest, SetWidgetParamCallbackTest003, TestSize.Level0)
{
    sptr<MockSetWidgetParamCallback> mockCallback = new (std::nothrow) MockSetWidgetParamCallback();
    EXPECT_NE(mockCallback, nullptr);

    auto service = Common::MakeShared<SetWidgetParamClientCallback>(mockCallback);
    EXPECT_NE(service, nullptr);

    WidgetParamNapi testWidgetParam = {};
    testWidgetParam.title = "test title";
    testWidgetParam.navigationButtonText = "test navigation";
    testWidgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    testWidgetParam.hasContext = false;

    auto mockModalCallback = Common::MakeShared<MockUserAuthModalCallback>();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_CALL(*mockCallback, OnSetRemoteAuthWidgetParam(_, _)).Times(1);
    int32_t result = service->OnSetRemoteAuthWidgetParam(testWidgetParam, mockModalCallback);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SetWidgetParamCallbackTest, SetWidgetParamCallbackTest004, TestSize.Level0)
{
    sptr<MockSetWidgetParamCallback> mockCallback = new (std::nothrow) MockSetWidgetParamCallback();
    EXPECT_NE(mockCallback, nullptr);

    auto service = Common::MakeShared<SetWidgetParamClientCallback>(mockCallback);
    EXPECT_NE(service, nullptr);

    WidgetParamNapi testWidgetParam = {};
    testWidgetParam.title = "";
    testWidgetParam.navigationButtonText = "";
    testWidgetParam.windowMode = WindowModeType::DIALOG_BOX;
    testWidgetParam.hasContext = true;

    auto mockModalCallback = Common::MakeShared<MockUserAuthModalCallback>();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_CALL(*mockCallback, OnSetRemoteAuthWidgetParam(_, _)).Times(1);
    int32_t result = service->OnSetRemoteAuthWidgetParam(testWidgetParam, mockModalCallback);
    EXPECT_EQ(result, SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

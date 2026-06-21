/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "widget_context_callback_impl.h"

#include <future>
#include <gmock/gmock.h>
#include "iam_ptr.h"
#include "mock_context.h"
#include "context_factory.h"
#include "widget_context.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace UserAuth {

class WidgetContextCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() ;

    void TearDown() ;
};

void WidgetContextCallbackImplTest::SetUpTestCase()
{
}

void WidgetContextCallbackImplTest::TearDownTestCase()
{
}

void WidgetContextCallbackImplTest::SetUp()
{
}

void WidgetContextCallbackImplTest::TearDown()
{
}

HWTEST_F(WidgetContextCallbackImplTest, WidgetContextCallbackImplOnResult_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    std::shared_ptr<ContextCallback> callback = Common::MakeShared<MockContextCallback>();
    WidgetContext *widgetContext = new WidgetContext(contextId, para, callback, nullptr, nullptr);
    int32_t authType = 0;
    auto contextCallback =
        Common::MakeShared<WidgetContextCallbackImpl>(std::shared_ptr<WidgetContext>(widgetContext), authType);
    ASSERT_NE(contextCallback, nullptr);
    int32_t result = 1;
    Attributes extraInfo;
    contextCallback->widgetContext_ = std::weak_ptr<WidgetContext>();
    contextCallback->OnResult(result, extraInfo.Serialize());
    ASSERT_EQ(para.tokenId, 0);
}

HWTEST_F(WidgetContextCallbackImplTest, WidgetContextCallbackImplOnResult_002, TestSize.Level0)
{
    std::shared_ptr<WidgetContext> widgetContext = nullptr;
    int32_t authType = 0;
    auto contextCallback = Common::MakeShared<WidgetContextCallbackImpl>(widgetContext, authType);
    ASSERT_NE(contextCallback, nullptr);
    int32_t result = 1;
    Attributes extraInfo;
    contextCallback->OnResult(result, extraInfo.Serialize());
}

HWTEST_F(WidgetContextCallbackImplTest, WidgetContextCallbackImplOnAcquireInfo_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    std::shared_ptr<ContextCallback> callback = Common::MakeShared<MockContextCallback>();
    WidgetContext *widgetContext = new WidgetContext(contextId, para, callback, nullptr, nullptr);
    int32_t authType = 0;
    auto contextCallback =
        Common::MakeShared<WidgetContextCallbackImpl>(std::shared_ptr<WidgetContext>(widgetContext), authType);
    ASSERT_NE(contextCallback, nullptr);

    int32_t module = 0;
    int32_t acquireInfo = 0;
    Attributes extraInfo;
    contextCallback->widgetContext_ = std::weak_ptr<WidgetContext>();
    contextCallback->OnAcquireInfo(module, acquireInfo, extraInfo.Serialize());

    sptr<IRemoteObject> object = contextCallback->AsObject();
    EXPECT_EQ(object, nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
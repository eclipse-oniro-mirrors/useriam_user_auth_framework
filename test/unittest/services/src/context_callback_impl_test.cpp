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

#include <gtest/gtest.h>

#include "context_callback_impl.h"
#include "iam_ptr.h"
#include "nlohmann/json.hpp"
#include "mock_user_auth_callback.h"
#include "mock_user_idm_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace std;
using namespace testing;
using namespace testing::ext;

class ContextCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void ContextCallbackImplTest::SetUpTestCase()
{
}

void ContextCallbackImplTest::TearDownTestCase()
{
}

void ContextCallbackImplTest::SetUp()
{
}

void ContextCallbackImplTest::TearDown()
{
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserAuthNull, TestSize.Level0)
{
    sptr<UserAuthCallbackInterface> callback(nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ASSERT_EQ(contextCallback, nullptr);
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserIdmNull, TestSize.Level0)
{
    sptr<IdmCallbackInterface> callback(nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ASSERT_EQ(contextCallback, nullptr);
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserAuth, TestSize.Level0)
{
    int32_t testResult = 66;
    auto testAttr = Common::MakeShared<Attributes>();
    ASSERT_TRUE(testAttr != nullptr);

    sptr<MockUserAuthCallback> mockCallback(new (nothrow) MockUserAuthCallback());
    ASSERT_TRUE(mockCallback != nullptr);
    EXPECT_CALL(*mockCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([&testResult, &testAttr](int32_t result, const Attributes &reqRet) {
            EXPECT_TRUE(testResult == result);
            EXPECT_TRUE(&reqRet == testAttr.get());
        });
    sptr<UserAuthCallbackInterface> callback = mockCallback;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ASSERT_NE(contextCallback, nullptr);
    contextCallback->OnAcquireInfo(static_cast<ExecutorRole>(0), 0, {});
    contextCallback->OnResult(testResult, *testAttr);
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserIdmOnResult, TestSize.Level0)
{
    int32_t testResult = 66;
    int32_t acquire = 20;
    auto testAttr = Common::MakeShared<Attributes>();
    ASSERT_TRUE(testAttr != nullptr);
    EXPECT_TRUE(testAttr->SetInt32Value(Attributes::ATTR_TIP_INFO, acquire));
    EXPECT_TRUE(testAttr->SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 2));
    EXPECT_TRUE(testAttr->SetInt32Value(Attributes::ATTR_FREEZING_TIME, 40));
    auto testMsg = testAttr->Serialize();

    auto notify = [](const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag) { return; };
    ContextCallbackNotifyListener::GetInstance().AddNotifier(notify);
    ContextCallbackNotifyListener::GetInstance().AddNotifier(nullptr);

    sptr<MockIdmCallback> mockCallback(new (nothrow) MockIdmCallback());
    ASSERT_TRUE(mockCallback != nullptr);
    EXPECT_CALL(*mockCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockCallback, OnAcquireInfo(_, _, _)).Times(1);
    sptr<IdmCallbackInterface> callback = mockCallback;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ASSERT_NE(contextCallback, nullptr);
    contextCallback->OnAcquireInfo(static_cast<ExecutorRole>(0), 0, testMsg);
    contextCallback->OnResult(testResult, *testAttr);
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserAuthOnAcquireInfo_001, TestSize.Level0)
{
    int32_t acquire = 9999;
    auto jsonExtraInfo = nlohmann::json({
        {"authResutlt", 0},
        {"authRemainAttempts", 5},
        {"lockoutDuration", 0}});
    std::string stringExtraInfo = jsonExtraInfo.dump();
    const std::vector<uint8_t> extraInfo(stringExtraInfo.data(), stringExtraInfo.data() + stringExtraInfo.length());

    auto testAttr = Common::MakeShared<Attributes>();
    ASSERT_TRUE(testAttr != nullptr);
    EXPECT_TRUE(testAttr->SetInt32Value(Attributes::ATTR_TIP_INFO, acquire));
    EXPECT_TRUE(testAttr->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo));
    auto testMsg = testAttr->Serialize();

    auto notify = [](const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag) { return; };
    ContextCallbackNotifyListener::GetInstance().AddNotifier(notify);

    sptr<MockIdmCallback> mockCallback(new (nothrow) MockIdmCallback());
    ASSERT_TRUE(mockCallback != nullptr);
    EXPECT_CALL(*mockCallback, OnAcquireInfo(_, _, _)).Times(1);
    sptr<IdmCallbackInterface> callback = mockCallback;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER_BEHAVIOR);
    ASSERT_NE(contextCallback, nullptr);
    contextCallback->OnAcquireInfo(static_cast<ExecutorRole>(0), 0, testMsg);
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserAuthOnAcquireInfo_002, TestSize.Level0)
{
    int32_t acquire = 9999;
    auto jsonExtraInfo = nlohmann::json({
        {"authResutlt", 1},
        {"authRemainAttempts", 5},
        {"lockoutDuration", 0}});
    std::string stringExtraInfo = jsonExtraInfo.dump();
    const std::vector<uint8_t> extraInfo(stringExtraInfo.data(), stringExtraInfo.data() + stringExtraInfo.length());

    auto testAttr = Common::MakeShared<Attributes>();
    ASSERT_TRUE(testAttr != nullptr);
    EXPECT_TRUE(testAttr->SetInt32Value(Attributes::ATTR_TIP_INFO, acquire));
    EXPECT_TRUE(testAttr->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo));
    auto testMsg = testAttr->Serialize();

    auto notify = [](const ContextCallbackNotifyListener::MetaData &metaData, TraceFlag flag) { return; };
    ContextCallbackNotifyListener::GetInstance().AddNotifier(notify);

    sptr<MockIdmCallback> mockCallback(new (nothrow) MockIdmCallback());
    ASSERT_TRUE(mockCallback != nullptr);
    EXPECT_CALL(*mockCallback, OnAcquireInfo(_, _, _)).Times(1);
    sptr<IdmCallbackInterface> callback = mockCallback;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER_SECURITY);
    ASSERT_NE(contextCallback, nullptr);
    contextCallback->OnAcquireInfo(static_cast<ExecutorRole>(0), 0, testMsg);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

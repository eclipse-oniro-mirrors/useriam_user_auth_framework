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
#include <gtest/gtest.h>

#include "context_factory.h"
#include "mock_user_auth_callback.h"
#include "mock_user_idm_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace std;
using namespace testing;
using namespace testing::ext;
class ContextFactoryTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void ContextFactoryTest::SetUpTestCase()
{
}

void ContextFactoryTest::TearDownTestCase()
{
}

void ContextFactoryTest::SetUp()
{
}

void ContextFactoryTest::TearDown()
{
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateSimpleAuth_001, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> challenge;
    sptr<IIamCallback> callback(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(callback, nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER_ALL);
    Authentication::AuthenticationPara para = {};
    auto context = factory->CreateSimpleAuthContext(para, contextCallback, true);
    ASSERT_NE(context, nullptr);
    EXPECT_NE(context->GetContextId(), 0U);
    ASSERT_EQ(context->GetContextType(), CONTEXT_SIMPLE_AUTH);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateSimpleAuth_002, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> challenge;
    // Error: callback is null
    sptr<IIamCallback> callback(nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER_ALL);
    Authentication::AuthenticationPara para = {};
    auto context = factory->CreateSimpleAuthContext(para, contextCallback, true);
    ASSERT_EQ(context, nullptr);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateIdentify_001, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> challenge;
    sptr<IIamCallback> callback(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(callback, nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_IDENTIFY);
    Identification::IdentificationPara para = {};
    auto context = factory->CreateIdentifyContext(para, contextCallback);
    ASSERT_NE(context, nullptr);
    EXPECT_NE(context->GetContextId(), 0U);
    ASSERT_EQ(context->GetContextType(), CONTEXT_IDENTIFY);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateIdentify_002, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> challenge;
    // Error: callback is null
    sptr<IIamCallback> callback(nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_IDENTIFY);
    Identification::IdentificationPara para = {};
    auto context = factory->CreateIdentifyContext(para, contextCallback);
    ASSERT_EQ(context, nullptr);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateEnrollContext_001, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> token;
    sptr<IIamCallback> callback(new (std::nothrow) MockIdmCallback());
    ASSERT_NE(callback, nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    Enrollment::EnrollmentPara para = {};
    auto context = factory->CreateEnrollContext(para, contextCallback, true);
    ASSERT_NE(context, nullptr);
    EXPECT_NE(context->GetContextId(), 0U);
    ASSERT_EQ(context->GetContextType(), CONTEXT_ENROLL);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateEnrollContext_002, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> token;
    // Error: callback is null
    sptr<IIamCallback> callback(nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    Enrollment::EnrollmentPara para = {};
    auto context = factory->CreateEnrollContext(para, contextCallback, true);
    ASSERT_EQ(context, nullptr);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateWidgetAuthContext_001, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> token;
    sptr<IIamCallback> callback(nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    EXPECT_EQ(ContextFactory::CreateWidgetAuthContext(contextCallback), nullptr);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateWidgetContext_001, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> token;
    sptr<IIamCallback> callback(new (std::nothrow) MockIdmCallback());
    ASSERT_NE(callback, nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ContextFactory::AuthWidgetContextPara para = {};
    auto context = factory->CreateWidgetContext(para, contextCallback, nullptr, nullptr);
    ASSERT_NE(context, nullptr);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateWidgetContext_002, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> token;
    sptr<IIamCallback> callback(nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ContextFactory::AuthWidgetContextPara para = {};
    auto context = factory->CreateWidgetContext(para, contextCallback, nullptr, nullptr);
    ASSERT_EQ(context, nullptr);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateDeleteContext_001, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> token;
    sptr<IIamCallback> callback(new (std::nothrow) MockIdmCallback());
    ASSERT_NE(callback, nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_DELETE_CREDENTIAL);
    Deletion::DeleteParam para = {};
    auto context = factory->CreateDeleteContext(para, contextCallback);
    ASSERT_NE(context, nullptr);
    EXPECT_NE(context->GetContextId(), 0U);
    ASSERT_EQ(context->GetContextType(), CONTEXT_DELETE);
}

HWTEST_F(ContextFactoryTest, ContextFactoryCreateDeleteContext_002, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    std::vector<uint8_t> token;
    // Error: callback is null
    sptr<IIamCallback> callback(nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_DELETE_CREDENTIAL);
    Deletion::DeleteParam para = {};
    auto context = factory->CreateDeleteContext(para, contextCallback);
    ASSERT_EQ(context, nullptr);
}

HWTEST_F(ContextFactoryTest, CreateRemoteAuthContext_001, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    Authentication::AuthenticationPara para = {};
    RemoteAuthContextParam remoteAuthContextParam = {};
    sptr<IIamCallback> callback(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(callback, nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER_ALL);
    factory->CreateRemoteAuthContext(para, remoteAuthContextParam, contextCallback);
}

HWTEST_F(ContextFactoryTest, CreateRemoteAuthContext_002, TestSize.Level0)
{
    auto factory = ContextFactory::GetInstance();
    ASSERT_NE(factory, nullptr);
    Authentication::AuthenticationPara para = {};
    RemoteAuthContextParam remoteAuthContextParam = {};
    remoteAuthContextParam.connectionName = "aaa";
    sptr<IIamCallback> callback(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(callback, nullptr);
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER_ALL);
    factory->CreateRemoteAuthContext(para, remoteAuthContextParam, contextCallback);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

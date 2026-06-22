/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "iam_executor_iauth_executor_hdi.h"

#include "iam_logger.h"
#include "iam_ptr.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;

#define LOG_TAG "USER_AUTH_EXECUTOR_TEST"
#define LOG_FILE_ID LOG_FILE_IAUTH_EXECUTOR_HDI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IAuthExecutorHdiTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IAuthExecutorHdiTest::SetUpTestCase()
{
}

void IAuthExecutorHdiTest::TearDownTestCase()
{
}

void IAuthExecutorHdiTest::SetUp()
{
}

void IAuthExecutorHdiTest::TearDown()
{
}

class IAuthExecutorHdiMock : public IAuthExecutorHdi {
public:
    ResultCode GetExecutorInfo(ExecutorInfo &info);
    ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo);
    ResultCode Cancel(uint64_t scheduleId);
    ResultCode SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg);
};

ResultCode IAuthExecutorHdiMock::GetExecutorInfo(ExecutorInfo &info)
{
    IAM_LOGE("method not implemented");
    return GENERAL_ERROR;
}

ResultCode IAuthExecutorHdiMock::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGE("method not implemented");
    return GENERAL_ERROR;
}

ResultCode IAuthExecutorHdiMock::Cancel(uint64_t scheduleId)
{
    IAM_LOGE("method not implemented");
    return GENERAL_ERROR;
}

ResultCode IAuthExecutorHdiMock::SendMessage(uint64_t scheduleId, int32_t srcRole,
    const std::vector<uint8_t> &msg)
{
    IAM_LOGE("method not implemented");
    return GENERAL_ERROR;
}

HWTEST_F(IAuthExecutorHdiTest, OnRegisterFinishTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    std::vector<uint64_t> templateIdList = {};
    std::vector<uint8_t> frameworkPublicKey = {};
    std::vector<uint8_t> extraInfo = {};
    EXPECT_EQ(authExecutorHdi->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, CancelTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    uint64_t scheduleId = 0;
    EXPECT_EQ(authExecutorHdi->Cancel(scheduleId), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, SendMessageTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    uint64_t scheduleId = 0;
    int32_t srcRole = 1;
    std::vector<uint8_t> msg = {};
    EXPECT_EQ(authExecutorHdi->SendMessage(scheduleId, srcRole, msg), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, GetExecutorInfoTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    ExecutorInfo info = {};
    EXPECT_EQ(authExecutorHdi->GetExecutorInfo(info), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, EnrollTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    uint64_t scheduleId = 0;
    EnrollParam param = {};
    std::shared_ptr<UserAuth::IExecuteCallback> callbackObj = nullptr;
    EXPECT_EQ(authExecutorHdi->Enroll(scheduleId, param, callbackObj), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, AuthenticateTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    uint64_t scheduleId = 0;
    AuthenticateParam param = {};
    std::shared_ptr<UserAuth::IExecuteCallback> callbackObj = nullptr;
    EXPECT_EQ(authExecutorHdi->Authenticate(scheduleId, param, callbackObj), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, CollectTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    uint64_t scheduleId = 0;
    CollectParam param = {};
    std::shared_ptr<UserAuth::IExecuteCallback> callbackObj = nullptr;
    EXPECT_EQ(authExecutorHdi->Collect(scheduleId, param, callbackObj), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, IdentifyTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    uint64_t scheduleId = 0;
    IdentifyParam param = {};
    std::shared_ptr<UserAuth::IExecuteCallback> callbackObj = nullptr;
    EXPECT_EQ(authExecutorHdi->Identify(scheduleId, param, callbackObj), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, DeleteTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    std::vector<uint64_t> templateIdList = {1, 2, 3};
    EXPECT_EQ(authExecutorHdi->Delete(templateIdList), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, SendCommandTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    PropertyMode commandId = PROPERTY_INIT_ALGORITHM;
    std::vector<uint8_t> extraInfo = {1, 2, 3};
    std::shared_ptr<UserAuth::IExecuteCallback> callbackObj = nullptr;
    EXPECT_EQ(authExecutorHdi->SendCommand(commandId, extraInfo, callbackObj), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, GetPropertyTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    std::vector<uint64_t> templateIdList = {0, 1, 2};
    std::vector<Attributes::AttributeKey> keys = {};
    Property property = {};
    EXPECT_EQ(authExecutorHdi->GetProperty(templateIdList, keys, property), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, SetCachedTemplatesTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    std::vector<uint64_t> templateIdList = {0, 1, 2};
    EXPECT_EQ(authExecutorHdi->SetCachedTemplates(templateIdList), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, NotifyCollectorReadyTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    uint64_t scheduleId = 0;
    EXPECT_EQ(authExecutorHdi->NotifyCollectorReady(scheduleId), GENERAL_ERROR);
}

HWTEST_F(IAuthExecutorHdiTest, AbandonTest, TestSize.Level0)
{
    auto authExecutorHdi = MakeShared<IAuthExecutorHdiMock>();
    uint64_t scheduleId = 0;
    DeleteParam param = {};
    std::shared_ptr<UserAuth::IExecuteCallback> callbackObj = nullptr;
    EXPECT_EQ(authExecutorHdi->Abandon(scheduleId, param, callbackObj), GENERAL_ERROR);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

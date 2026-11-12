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

#include "iam_ptr.h"

#include "credential_info_impl.h"
#include "enrollment_impl.h"
#include "resource_node_pool.h"
#include "hdi_type_aliases.h"
#include "mock_iuser_auth_interface.h"
#include "mock_resource_node.h"
#include "mock_schedule_node_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
class EnrollmentImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void EnrollmentImplTest::SetUpTestCase()
{
}

void EnrollmentImplTest::TearDownTestCase()
{
}

void EnrollmentImplTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void EnrollmentImplTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(EnrollmentImplTest, EnrollmentHdiError, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginEnrollmentExt(_, _, _)).WillRepeatedly(Return(1));

    auto enrollment = std::make_shared<EnrollmentImpl>(para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(enrollment->Start(scheduleList, nullptr));
}

HWTEST_F(EnrollmentImplTest, EnrollmentHdiEmpty, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginEnrollmentExt(_, _, _)).WillRepeatedly(Return(0));

    auto enroll = std::make_shared<EnrollmentImpl>(para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(enroll->Start(scheduleList, nullptr));
}

/**
 * @tc.name: enroll_update
 * @tc.desc: verify hdi enroll
 * @tc.type: FUNC
 * @tc.require: issueI5NXMW
 */
HWTEST_F(EnrollmentImplTest, EnrollmentUpdateHdiError, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, UpdateEnrollmentResult(para.userId, _, _)).WillRepeatedly(Return(1));

    auto enroll = std::make_shared<EnrollmentImpl>(para);
    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    uint64_t credentialId = 0;
    std::shared_ptr<CredentialInfoInterface> info = nullptr;
    std::shared_ptr<UpdatePinParamInterface> pinInfo = nullptr;
    std::optional<uint64_t> secUserId = std::nullopt;
    EXPECT_FALSE(enroll->Update(scheduleResult, credentialId, info, pinInfo, secUserId));
}

HWTEST_F(EnrollmentImplTest, EnrollmentUpdateHdiSuccessful_001, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    constexpr uint64_t credentialIdRet = 0x12;
    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    auto fillUpInfos = [](HdiEnrollResultInfo &infoRet) {
        HdiCredentialInfo oldInfo = {
            .credentialId = 1,
            .executorIndex = 2,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(0),
            .executorMatcher = 5,
            .executorSensorHint = 6,
        };
        HdiEnrollResultInfo info = {
            .credentialId = credentialIdRet,
            .oldInfo = oldInfo,
        };
        infoRet = info;
    };
    EXPECT_CALL(*mock, UpdateEnrollmentResult(para.userId, _, _))
        .WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));

    auto enroll = std::make_shared<EnrollmentImpl>(para);
    enroll->SetIsUpdate(true);
    EngCredentialInfo oldInfo = {};
    std::shared_ptr<CredentialInfoInterface> info = std::make_shared<CredentialInfoImpl>(para.userId, oldInfo);
    uint64_t credentialId = 0;
    std::shared_ptr<UpdatePinParamInterface> pinInfo = nullptr;
    std::optional<uint64_t> secUserId = std::nullopt;
    EXPECT_TRUE(enroll->Update(scheduleResult, credentialId, info, pinInfo, secUserId));

    // test return values
    EXPECT_EQ(credentialId, credentialIdRet);
    EXPECT_EQ(info->GetCredentialId(), 1U);
    EXPECT_EQ(info->GetAuthType(), static_cast<AuthType>(0));
    EXPECT_EQ(info->GetExecutorIndex(), 2U);
    EXPECT_EQ(info->GetUserId(), 0x11);
    EXPECT_EQ(info->GetTemplateId(), 3U);
    EXPECT_EQ(info->GetExecutorMatcher(), 5U);
    EXPECT_EQ(info->GetExecutorSensorHint(), 6U);
}

HWTEST_F(EnrollmentImplTest, EnrollmentUpdateHdiSuccessful_002, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 1206;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = PIN;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, UpdateEnrollmentResult(_, _, _)).WillRepeatedly(Return(0));
    auto enroll = std::make_shared<EnrollmentImpl>(para);
    enroll->SetIsUpdate(false);

    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    std::shared_ptr<CredentialInfoInterface> info = nullptr;
    std::shared_ptr<UpdatePinParamInterface> pinInfo = nullptr;
    uint64_t credentialId = 0;
    std::optional<uint64_t> secUserId = std::nullopt;
    EXPECT_FALSE(enroll->Update(scheduleResult, credentialId, info, pinInfo, secUserId));

    EXPECT_CALL(*mock, GetUserInfo(_, _, _, _)).WillRepeatedly(Return(1));
    enroll = std::make_shared<EnrollmentImpl>(para);
    EXPECT_FALSE(enroll->Update(scheduleResult, credentialId, info, pinInfo, secUserId));
}

HWTEST_F(EnrollmentImplTest, EnrollmentImplTestStart_001, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    constexpr uint64_t executorIndex = 60;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CancelEnrollment(_))
        .Times(2)
        .WillOnce(Return(HDF_SUCCESS))
        .WillOnce(Return(HDF_FAILURE));
    EXPECT_CALL(*mockHdi, BeginEnrollmentExt(_, _, _))
        .WillRepeatedly(
            [](const std::vector<uint8_t> &authToken, const HdiEnrollParamExt &param,
                HdiScheduleInfo &info) {
                info.authType = HdiAuthType::FACE;
                info.executorMatcher = 10;
                info.executorIndexes.push_back(60);
                std::vector<uint8_t> executorMessages;
                executorMessages.resize(1);
                info.executorMessages.push_back(executorMessages);
                info.scheduleId = 20;
                info.scheduleMode = ScheduleMode::IDENTIFY;
                info.templateIds.push_back(30);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, FACE, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto enroll = std::make_shared<EnrollmentImpl>(para);
    EXPECT_NE(enroll, nullptr);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(enroll->Start(scheduleList, callback));
    EXPECT_TRUE(enroll->Cancel());

    EXPECT_TRUE(enroll->Start(scheduleList, callback));
    EXPECT_FALSE(enroll->Cancel());

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
}

HWTEST_F(EnrollmentImplTest, EnrollmentImplTestStart_002, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 34567;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = PIN;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginEnrollmentExt(_, _, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(*mock, GetUserInfo(_, _, _, _))
        .WillOnce(Return(1))
        .WillRepeatedly(
            [](int32_t userId, uint64_t &secureUid, int32_t &pinSubType,
                std::vector<HdiEnrolledInfo> &infos) {
                secureUid = 1;
                pinSubType = static_cast<PinSubType>(10000);
                HdiEnrolledInfo info = {
                    .enrolledId = 200,
                    .authType = static_cast<HdiAuthType>(1),
                };
                infos.push_back(info);
                return 0;
            }
        );

    auto enroll = std::make_shared<EnrollmentImpl>(para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_FALSE(enroll->Start(scheduleList, callback));

    enroll->SetIsUpdate(true);
    EXPECT_FALSE(enroll->Start(scheduleList, callback));

    enroll = std::make_shared<EnrollmentImpl>(para);
    enroll->SetIsUpdate(true);
    EXPECT_FALSE(enroll->Start(scheduleList, callback));
    EXPECT_FALSE(enroll->Start(scheduleList, callback));

    enroll = std::make_shared<EnrollmentImpl>(para);
    enroll->SetIsUpdate(false);
    EXPECT_FALSE(enroll->Start(scheduleList, callback));
}

HWTEST_F(EnrollmentImplTest, SetLatestErrorTest, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;

    auto enrollment = std::make_shared<EnrollmentImpl>(para);
    EXPECT_NO_THROW(enrollment->SetLatestError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(EnrollmentImplTest, EnrollmentWithAdditionalInfoTest, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.additionalInfo = "test_additional_info_for_enrollment";

    auto enrollment = std::make_shared<EnrollmentImpl>(para);
    EXPECT_NE(enrollment, nullptr);
    EXPECT_EQ(enrollment->GetUserId(), 0x11);
}

HWTEST_F(EnrollmentImplTest, EnrollmentWithEmptyAdditionalInfoTest, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x12;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = PIN;
    para.additionalInfo = "";

    auto enrollment = std::make_shared<EnrollmentImpl>(para);
    EXPECT_NE(enrollment, nullptr);
    EXPECT_EQ(enrollment->GetUserId(), 0x12);
}

HWTEST_F(EnrollmentImplTest, EnrollmentStartWithAdditionalInfoTest, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x13;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.additionalInfo = "additional_info_for_start_test";
    constexpr uint64_t executorIndex = 61;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginEnrollmentExt(_, _, _))
        .WillRepeatedly(
            [](const std::vector<uint8_t> &authToken, const HdiEnrollParamExt &param,
                HdiScheduleInfo &info) {
                EXPECT_EQ(param.additionalInfo, "additional_info_for_start_test");
                info.authType = HdiAuthType::FACE;
                info.executorMatcher = 10;
                info.executorIndexes.push_back(61);
                std::vector<uint8_t> executorMessages;
                executorMessages.resize(1);
                info.executorMessages.push_back(executorMessages);
                info.scheduleId = 21;
                info.scheduleMode = ScheduleMode::ENROLL;
                info.templateIds.push_back(31);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, FACE, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto enroll = std::make_shared<EnrollmentImpl>(para);
    EXPECT_NE(enroll, nullptr);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(enroll->Start(scheduleList, callback));

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
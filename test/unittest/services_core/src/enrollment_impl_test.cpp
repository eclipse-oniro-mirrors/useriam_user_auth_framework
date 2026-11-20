/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "enrollment_impl.h"

#include <gtest/gtest.h>

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
}

void EnrollmentImplTest::TearDown()
{
}

HWTEST_F(EnrollmentImplTest, EngineUnavailableTest, TestSize.Level0)
{
    Enrollment::EnrollmentPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;

    auto enrollment = std::make_shared<EnrollmentImpl>(para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(enrollment->Start(scheduleList, nullptr));

    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    uint64_t credentialId = 0;
    std::shared_ptr<CredentialInfoInterface> info = nullptr;
    std::shared_ptr<UpdatePinParamInterface> pinInfo = nullptr;
    std::optional<uint64_t> secUserId = std::nullopt;
    EXPECT_FALSE(enrollment->Update(scheduleResult, credentialId, info, pinInfo, secUserId));

    enrollment->running_ = true;
    EXPECT_FALSE(enrollment->Cancel());
}

HWTEST_F(EnrollmentImplTest, EnrollmentParaWithAdditionalInfoTest, TestSize.Level0)
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

HWTEST_F(EnrollmentImplTest, EnrollmentParaWithEmptyAdditionalInfoTest, TestSize.Level0)
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
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

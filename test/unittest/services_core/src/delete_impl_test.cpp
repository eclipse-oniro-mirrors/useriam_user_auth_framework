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

#include "delete_impl.h"
#include <gtest/gtest.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
class DeleteImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void DeleteImplTest::SetUpTestCase()
{
}

void DeleteImplTest::TearDownTestCase()
{
}

void DeleteImplTest::SetUp()
{
}

void DeleteImplTest::TearDown()
{
}

HWTEST_F(DeleteImplTest, BadHdiTest, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;
    auto abandon = std::make_shared<DeleteImpl>(para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    bool isStartSchedule = false;
    std::vector<EngCredentialInfo> credentialInfos = {};
    EXPECT_FALSE(abandon->Start(scheduleList, nullptr, isStartSchedule, credentialInfos));

    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    std::shared_ptr<CredentialInfoInterface> info = nullptr;
    EXPECT_FALSE(abandon->Update(scheduleResult, info));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

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

#include "authentication_impl.h"
#include <gtest/gtest.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class AuthenticationImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void AuthenticationImplTest::SetUpTestCase()
{
}

void AuthenticationImplTest::TearDownTestCase()
{
}

void AuthenticationImplTest::SetUp()
{
}

void AuthenticationImplTest::TearDown()
{
}

HWTEST_F(AuthenticationImplTest, BadHdiTest, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);

    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    EXPECT_FALSE(authentication->Start(scheduleList, acquireInfoCallback, nullptr));

    std::vector<uint8_t> scheduleResult;
    Authentication::AuthResultInfo info = {};
    EXPECT_FALSE(authentication->Update(scheduleResult, info, acquireInfoCallback));

    authentication->running_ = true;
    EXPECT_FALSE(authentication->Cancel());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

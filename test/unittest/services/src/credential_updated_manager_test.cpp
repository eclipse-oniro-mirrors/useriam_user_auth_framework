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

#include "credential_updated_manager_test.h"

#include <unistd.h>

#include "credential_updated_manager.h"
#include "delete_impl.h"
#include "enrollment.h"
#include "event_listener_manager.h"
#include "publish_event_adapter.h"
#include "system_param_manager.h"
#include "user_idm_database_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
namespace {
constexpr const int32_t TEST_USER_ID = 100;
constexpr const int32_t TEST_CALLER_TYPE = 1;
constexpr const uint64_t TEST_CREDENTIAL_ID = 123456789;
constexpr const uint64_t TEST_SCHEDULE_ID = 111111111;
const std::string TEST_CALLER_NAME = "test_caller";
} // namespace

void CredentialUpdatedManagerTest::SetUpTestCase()
{}

void CredentialUpdatedManagerTest::TearDownTestCase()
{}

void CredentialUpdatedManagerTest::SetUp()
{}

void CredentialUpdatedManagerTest::TearDown()
{}

HWTEST_F(CredentialUpdatedManagerTest, ProcessCredentialDeletedTest, TestSize.Level0)
{
    Deletion::DeleteParam deletePara;
    deletePara.userId = TEST_USER_ID;
    deletePara.callerName = TEST_CALLER_NAME;
    deletePara.callerType = TEST_CALLER_TYPE;

    auto& instance = CredentialUpdatedManager::GetInstance();
    EXPECT_NO_THROW(instance.ProcessCredentialDeleted(deletePara, TEST_CREDENTIAL_ID, FACE));
}

HWTEST_F(CredentialUpdatedManagerTest, ProcessCredentialEnrolledTest, TestSize.Level0)
{
    Enrollment::EnrollmentPara enrollPara;
    enrollPara.userId = TEST_USER_ID;
    enrollPara.authType = PIN;
    enrollPara.callerName = TEST_CALLER_NAME;
    enrollPara.callerType = TEST_CALLER_TYPE;

    HdiEnrollResultInfo resultInfo;
    resultInfo.oldInfo.credentialId = TEST_CREDENTIAL_ID;

    auto& instance = CredentialUpdatedManager::GetInstance();
    EXPECT_NO_THROW(instance.ProcessCredentialEnrolled(enrollPara, resultInfo, true, TEST_SCHEDULE_ID));
    EXPECT_NO_THROW(instance.ProcessCredentialEnrolled(enrollPara, resultInfo, false, TEST_SCHEDULE_ID));

    enrollPara.authType = FACE;
    EXPECT_NO_THROW(instance.ProcessCredentialEnrolled(enrollPara, resultInfo, true, TEST_SCHEDULE_ID));
    EXPECT_NO_THROW(instance.ProcessCredentialEnrolled(enrollPara, resultInfo, false, TEST_SCHEDULE_ID));
}

HWTEST_F(CredentialUpdatedManagerTest, ProcessUserDeletedTest, TestSize.Level0)
{
    auto& instance = CredentialUpdatedManager::GetInstance();
    EXPECT_NO_THROW(instance.ProcessUserDeleted(TEST_USER_ID));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

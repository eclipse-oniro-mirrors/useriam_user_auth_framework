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

#include "service_unload_manager_test.h"

#include "service_unload_manager.h"
#include "system_param_manager.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SERVICE_UNLOAD_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ServiceUnloadManagerTest::SetUpTestCase()
{
}

void ServiceUnloadManagerTest::TearDownTestCase()
{
}

void ServiceUnloadManagerTest::SetUp()
{
}

void ServiceUnloadManagerTest::TearDown()
{
}

/**
 * @tc.name: StartSubscribe_001
 * @tc.desc: Test StartSubscribe basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, StartSubscribe_001, TestSize.Level0)
{
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().StartSubscribe());
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().StartSubscribe());
}

/**
 * @tc.name: OnCredentialCheckedChange_001
 * @tc.desc: Test OnCredentialCheckedChange with same value (no change)
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnCredentialCheckedChange_001, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(false));
}

/**
 * @tc.name: OnCredentialCheckedChange_002
 * @tc.desc: Test OnCredentialCheckedChange changing from false to true
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnCredentialCheckedChange_002, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(true));
}

/**
 * @tc.name: OnCredentialCheckedChange_003
 * @tc.desc: Test OnCredentialCheckedChange changing from true to false
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnCredentialCheckedChange_003, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(true));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(false));
}

/**
 * @tc.name: OnIsPinEnrolledChange_001
 * @tc.desc: Test OnIsPinEnrolledChange with same value (no change)
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnIsPinEnrolledChange_001, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(false));
}

/**
 * @tc.name: OnIsPinEnrolledChange_002
 * @tc.desc: Test OnIsPinEnrolledChange changing from false to true
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnIsPinEnrolledChange_002, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(true));
}

/**
 * @tc.name: OnIsPinEnrolledChange_003
 * @tc.desc: Test OnIsPinEnrolledChange changing from true to false
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnIsPinEnrolledChange_003, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(true));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(false));
}

/**
 * @tc.name: OnStartSaChange_001
 * @tc.desc: Test OnStartSaChange with same value (no change)
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnStartSaChange_001, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(false));
}

/**
 * @tc.name: OnStartSaChange_002
 * @tc.desc: Test OnStartSaChange changing from false to true
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnStartSaChange_002, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(true));
}

/**
 * @tc.name: OnStartSaChange_003
 * @tc.desc: Test OnStartSaChange changing from true to false
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnStartSaChange_003, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(true));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(false));
}

/**
 * @tc.name: OnFwkReady_001
 * @tc.desc: Test OnFwkReady basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnFwkReady_001, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    bool isStopSa = false;
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnFwkReady(isStopSa));
}

/**
 * @tc.name: OnFwkReady_002
 * @tc.desc: Test OnFwkReady with PIN enrolled
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnFwkReady_002, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(true));
    bool isStopSa = false;
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnFwkReady(isStopSa));
}

/**
 * @tc.name: OnFwkReady_003
 * @tc.desc: Test OnFwkReady without PIN enrolled
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnFwkReady_003, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(false));
    bool isStopSa = false;
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnFwkReady(isStopSa));
}

/**
 * @tc.name: TimerStart_001
 * @tc.desc: Test timer start when all conditions are met
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, TimerStart_001, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(true));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(true));
}

/**
 * @tc.name: TimerStart_002
 * @tc.desc: Test timer not start when PIN is enrolled
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, TimerStart_002, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(true));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(true));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(true));
}

/**
 * @tc.name: TimerStart_003
 * @tc.desc: Test timer not start when credential not checked
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, TimerStart_003, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(true));
}

/**
 * @tc.name: TimerStart_004
 * @tc.desc: Test timer not start when startSa is false
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, TimerStart_004, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(true));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnStartSaChange(false));
}

/**
 * @tc.name: OnTimeout_001
 * @tc.desc: Test OnTimeout basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnTimeout_001, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnTimeout());
}

/**
 * @tc.name: OnTimeout_002
 * @tc.desc: Test OnTimeout with PIN enrolled (should not stop SA)
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnTimeout_002, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(true));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnTimeout());
}

/**
 * @tc.name: OnTimeout_003
 * @tc.desc: Test OnTimeout without PIN enrolled
 * @tc.type: FUNC
 */
HWTEST_F(ServiceUnloadManagerTest, OnTimeout_003, TestSize.Level0)
{
    ServiceUnloadManager::GetInstance().StartSubscribe();
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(false));
    EXPECT_NO_THROW(ServiceUnloadManager::GetInstance().OnTimeout());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

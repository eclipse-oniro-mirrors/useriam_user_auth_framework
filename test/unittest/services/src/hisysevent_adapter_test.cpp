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

#include "hisysevent_adapter_test.h"

#include "hisysevent_adapter.h"

#include <cinttypes>

#include "hisysevent.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_time.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_HISYSEVENT_ADAPTER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void HiSysEventAdapterTest::SetUpTestCase()
{
}

void HiSysEventAdapterTest::TearDownTestCase()
{
}

void HiSysEventAdapterTest::SetUp()
{
}

void HiSysEventAdapterTest::TearDown()
{
}

HWTEST_F(HiSysEventAdapterTest, ReportRemoteExecuteProcTest001, TestSize.Level3)
{
    RemoteExecuteTrace trace = {};
    EXPECT_NO_THROW(ReportRemoteExecuteProc(trace));
}

HWTEST_F(HiSysEventAdapterTest, ReportSaLoadDriverFailureTest001, TestSize.Level3)
{
    SaLoadDriverFailureTrace trace = {};
    EXPECT_NO_THROW(ReportSaLoadDriverFailure(trace));
}

HWTEST_F(HiSysEventAdapterTest, ReportIsCredentialEnrolledMismatchTest001, TestSize.Level3)
{
    IsCredentialEnrolledMismatchTrace trace = {};
    EXPECT_NO_THROW(ReportIsCredentialEnrolledMismatch(trace));
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

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

#include "trace_test.h"

#include <climits>

#include "attributes.h"

#include "securec.h"
#include "trace.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void TraceTest::SetUpTestCase()
{
}

void TraceTest::TearDownTestCase()
{
}

void TraceTest::SetUp()
{
}

void TraceTest::TearDown()
{
}

HWTEST_F(TraceTest, CopyMetaDataToTraceInfo_001, TestSize.Level0)
{
    Trace *trace = new Trace();
    EXPECT_NE(trace, nullptr);
    ContextCallbackNotifyListener::MetaData metaData;
    TraceFlag flag = TRACE_FLAG_DEFAULT;
    UserAuthTrace info;
    metaData.remoteUdid = std::nullopt;
    metaData.localUdid = std::nullopt;
    metaData.connectionName = std::nullopt;
    metaData.authFinishReason = "";
    trace->CopyMetaDataToTraceInfo(metaData, info);
}

HWTEST_F(TraceTest, CopyMetaDataToTraceInfo_002, TestSize.Level0)
{
    Trace *trace = new Trace();
    EXPECT_NE(trace, nullptr);
    ContextCallbackNotifyListener::MetaData metaData;
    TraceFlag flag = TRACE_FLAG_DEFAULT;
    UserAuthTrace info;
    metaData.remoteUdid = "1";
    metaData.localUdid = "1";
    metaData.connectionName = "1";
    trace->CopyMetaDataToTraceInfo(metaData, info);
}

HWTEST_F(TraceTest, ProcessUserAuthFwkEvent_001, TestSize.Level0)
{
    Trace *trace = new Trace();
    EXPECT_NE(trace, nullptr);
    ContextCallbackNotifyListener::MetaData metaData;
    metaData.operationType = TRACE_AUTH_USER_SECURITY;
    metaData.callerName = "";
    metaData.atl = std::nullopt;
    metaData.authType = std::nullopt;
    metaData.remoteUdid = "";
    metaData.localUdid = "";
    metaData.connectionName = "";
    metaData.authFinishReason = std::nullopt;
    TraceFlag flag = TRACE_FLAG_DEFAULT;
    trace->ProcessUserAuthFwkEvent(metaData, flag);
}

HWTEST_F(TraceTest, ProcessUserAuthFwkEvent_002, TestSize.Level0)
{
    Trace *trace = new Trace();
    EXPECT_NE(trace, nullptr);
    ContextCallbackNotifyListener::MetaData metaData;
    TraceFlag flag = TRACE_FLAG_DEFAULT;
    metaData.callerName = "TEST";
    trace->ProcessUserAuthFwkEvent(metaData, flag);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
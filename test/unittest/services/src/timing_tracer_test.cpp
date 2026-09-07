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

#include "timing_tracer_test.h"

#include "timing_tracer.h"

#include <thread>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void TimingTracerTest::SetUpTestCase()
{
}

void TimingTracerTest::TearDownTestCase()
{
}

void TimingTracerTest::SetUp()
{
}

void TimingTracerTest::TearDown()
{
}

HWTEST_F(TimingTracerTest, TestNotStarted, TestSize.Level0)
{
    TimingTracer tracer;
    EXPECT_GE(tracer.TotalMs(), 0u);
    EXPECT_GE(tracer.LocalMs(), 0u);
    EXPECT_GE(tracer.ExportTrace(), "");
}

HWTEST_F(TimingTracerTest, TestStartFinishZero, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.Finish();
    EXPECT_GE(tracer.TotalMs(), 0u);
    EXPECT_GE(tracer.LocalMs(), 0u);
}

HWTEST_F(TimingTracerTest, TestTotalDuration, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.Finish();
    EXPECT_GE(tracer.TotalMs(), 1u);
}

HWTEST_F(TimingTracerTest, TestLocalEqualsTotalWhenNoWait, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.Finish();
    EXPECT_GE(tracer.TotalMs(), tracer.LocalMs());
}

HWTEST_F(TimingTracerTest, TestPairedWait, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    tracer.EnterWait(static_cast<StageId>(201));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.ExitWait(static_cast<StageId>(202));

    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.Finish();

    EXPECT_GE(tracer.TotalMs(), 3u);
    EXPECT_GE(tracer.TotalMs() - tracer.LocalMs(), 1u);
}

HWTEST_F(TimingTracerTest, TestWaitClosedByNextPoint, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();

    tracer.EnterWait(static_cast<StageId>(201));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.Mark(static_cast<StageId>(203));

    tracer.Finish();

    EXPECT_GE(tracer.TotalMs(), 1u);
    EXPECT_GE(tracer.TotalMs() - tracer.LocalMs(), 1u);
}

HWTEST_F(TimingTracerTest, TestUnclosedWaitChargedToEnd, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();

    tracer.EnterWait(static_cast<StageId>(201));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    tracer.Finish();

    EXPECT_GE(tracer.TotalMs(), 1u);
    EXPECT_GE(tracer.LocalMs(), 0u);
}

HWTEST_F(TimingTracerTest, TestExportTrace, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.Mark(StageId::S_CONTEXT_START);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.Mark(StageId::S_BEGIN_SCHEDULE_START);
    tracer.Finish();

    std::string trace = tracer.ExportTrace();
    EXPECT_FALSE(trace.empty());
    EXPECT_NE(trace.find("1:"), std::string::npos);
    EXPECT_NE(trace.find("2:"), std::string::npos);
}

HWTEST_F(TimingTracerTest, TestLocalMsUnderflowProtection, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.EnterWait(static_cast<StageId>(201));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.Finish();
    EXPECT_GE(tracer.LocalMs(), 0u);
}

HWTEST_F(TimingTracerTest, TestMultipleWaitRegions, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();

    tracer.EnterWait(static_cast<StageId>(201));
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    tracer.ExitWait(static_cast<StageId>(202));

    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    tracer.EnterWait(static_cast<StageId>(203));
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    tracer.ExitWait(static_cast<StageId>(204));

    EXPECT_NO_THROW(tracer.Finish());
}

HWTEST_F(TimingTracerTest, TestConsecutiveMarks, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.Mark(StageId::S_CONTEXT_START);
    tracer.Mark(StageId::S_BEGIN_SCHEDULE_START);
    tracer.Mark(StageId::S_BEGIN_SCHEDULE_END);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.Finish();

    std::string trace = tracer.ExportTrace();
    EXPECT_FALSE(trace.empty());
    EXPECT_NE(trace.find("1:"), std::string::npos);
    EXPECT_NE(trace.find("2:"), std::string::npos);
    EXPECT_NE(trace.find("3:"), std::string::npos);
}

HWTEST_F(TimingTracerTest, TestAuthTipMs, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.Mark(StageId::S_ON_TIP_AUTH_SUCC);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_NO_THROW(tracer.Finish());
}

HWTEST_F(TimingTracerTest, TestRestartResetsState, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.Mark(StageId::S_CONTEXT_START);
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    tracer.Finish();

    tracer.Start();
    EXPECT_NO_THROW(tracer.Finish());
}

HWTEST_F(TimingTracerTest, TestFinishBeforeStart, TestSize.Level0)
{
    TimingTracer tracer;
    EXPECT_NO_THROW(tracer.Finish());
}

HWTEST_F(TimingTracerTest, TestMarkBeforeStart, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Mark(StageId::S_CONTEXT_START);
    tracer.Start();
    tracer.Finish();

    std::string trace = tracer.ExportTrace();
    EXPECT_EQ(trace.find("1:"), std::string::npos);
}

HWTEST_F(TimingTracerTest, TestExportTraceEmptyPoints, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.Finish();

    std::string trace = tracer.ExportTrace();
    EXPECT_TRUE(trace.empty());
}

HWTEST_F(TimingTracerTest, TestExportTraceFormat, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.Mark(StageId::S_CONTEXT_START);
    tracer.Mark(StageId::S_BEGIN_SCHEDULE_START);
    tracer.Finish();

    std::string trace = tracer.ExportTrace();
    EXPECT_FALSE(trace.empty());
    EXPECT_NE(trace.find("1:"), std::string::npos);
    EXPECT_NE(trace.find("2:"), std::string::npos);
}

HWTEST_F(TimingTracerTest, TestEnterExitWaitWithoutStart, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.EnterWait(static_cast<StageId>(201));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.ExitWait(static_cast<StageId>(202));

    tracer.Start();
    EXPECT_NO_THROW(tracer.Finish());
}

HWTEST_F(TimingTracerTest, TestMultipleAuthTipMarks, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.Mark(StageId::S_ON_TIP_AUTH_SUCC);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.Mark(StageId::S_ON_TIP_AUTH_SUCC);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_NO_THROW(tracer.Finish());
}

HWTEST_F(TimingTracerTest, TestNestedWaitRegions, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();

    tracer.EnterWait(static_cast<StageId>(201));
    tracer.EnterWait(static_cast<StageId>(202));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracer.ExitWait(static_cast<StageId>(203));
    tracer.ExitWait(static_cast<StageId>(204));

    EXPECT_NO_THROW(tracer.Finish());
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

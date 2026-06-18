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

#include "thread_handler_impl_test.h"

#include "thread_handler_impl.h"

#include <cstdint>
#include <functional>
#include <future>
#include <memory>

#include "nocopyable.h"
#include "thread_handler_manager.h"

#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_THREAD_HANDLER_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ThreadHandlerImplTest::SetUpTestCase()
{
}

void ThreadHandlerImplTest::TearDownTestCase()
{
}

void ThreadHandlerImplTest::SetUp()
{
}

void ThreadHandlerImplTest::TearDown()
{
}

HWTEST_F(ThreadHandlerImplTest, PostTaskTest001, TestSize.Level3)
{
    std::string name = "";
    ThreadHandlerImpl impl(name, false);
    EXPECT_NO_THROW(impl.PostTask([]() {}));
}

HWTEST_F(ThreadHandlerImplTest, PostTaskTest002, TestSize.Level3)
{
    std::string name = "";
    ThreadHandlerImpl impl(name, true);
    EXPECT_NO_THROW(impl.PostTask([]() {}));
}

HWTEST_F(ThreadHandlerImplTest, EnsureTaskTest001, TestSize.Level3)
{
    std::string name = "";
    ThreadHandlerImpl impl(name, true);
    EXPECT_NO_THROW(impl.EnsureTask([]() {}));
}

HWTEST_F(ThreadHandlerImplTest, SuspendTest001, TestSize.Level3)
{
    std::string name = "";
    ThreadHandlerImpl impl(name, true);
    EXPECT_NO_THROW(impl.Suspend());
}

HWTEST_F(ThreadHandlerImplTest, SuspendTest002, TestSize.Level3)
{
    std::string name = "";
    ThreadHandlerImpl impl(name, false);
    EXPECT_NO_THROW(impl.Suspend());
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

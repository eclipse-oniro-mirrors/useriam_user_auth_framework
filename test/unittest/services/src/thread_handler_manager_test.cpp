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

#include "thread_handler_manager_test.h"

#include "thread_handler_manager.h"

#include <map>

#include "iam_check.h"
#include "iam_ptr.h"
#include "thread_handler_impl.h"
#include "thread_handler_singleton_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ThreadHandlerManagerTest::SetUpTestCase()
{
}

void ThreadHandlerManagerTest::TearDownTestCase()
{
}

void ThreadHandlerManagerTest::SetUp()
{
}

void ThreadHandlerManagerTest::TearDown()
{
}

HWTEST_F(ThreadHandlerManagerTest, CreateThreadHandlerTest001, TestSize.Level3)
{
    std::string name = "";
    EXPECT_EQ(ThreadHandlerManager::GetInstance().CreateThreadHandler(name), true);
    EXPECT_EQ(ThreadHandlerManager::GetInstance().CreateThreadHandler(name), false);
}

HWTEST_F(ThreadHandlerManagerTest, DestroyThreadHandlerTest001, TestSize.Level3)
{
    std::string name = "";
    EXPECT_NO_THROW(ThreadHandlerManager::GetInstance().DestroyThreadHandler(name));

    ThreadHandlerManager::GetInstance().CreateThreadHandler(name);
    EXPECT_NO_THROW(ThreadHandlerManager::GetInstance().DestroyThreadHandler(name));
}

HWTEST_F(ThreadHandlerManagerTest, DestroyThreadHandlerTest002, TestSize.Level3)
{
    EXPECT_NO_THROW(ThreadHandlerManager::GetInstance().DestroyThreadHandler(SINGLETON_THREAD_NAME));
}

HWTEST_F(ThreadHandlerManagerTest, PostTaskTest001, TestSize.Level3)
{
    std::string name = "";
    EXPECT_NO_THROW(ThreadHandlerManager::GetInstance().PostTask(name, []() {}));
}

HWTEST_F(ThreadHandlerManagerTest, PostTaskTest002, TestSize.Level3)
{
    std::string name = "";
    ThreadHandlerManager::GetInstance().CreateThreadHandler(name);
    EXPECT_NO_THROW(ThreadHandlerManager::GetInstance().PostTask(name, []() {}));
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef IAM_MOCK_THREAD_HANDLER_H
#define IAM_MOCK_THREAD_HANDLER_H

#include <gmock/gmock.h>

#include <future>

#include "singleton.h"
#include "thread_pool.h"

#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockThreadHandler final : public ThreadHandler {
public:
    MOCK_METHOD2(PostTask, void(const Task &task, uint32_t timeoutSec));
    MOCK_METHOD1(EnsureTask, void(const Task &task));
    MOCK_METHOD0(Suspend, void());
    static std::shared_ptr<ThreadHandler> InvokeDirectly()
    {
        using namespace testing;
        auto handler = std::make_shared<MockThreadHandler>();
        EXPECT_CALL(*handler, PostTask(_, _)).Times(AnyNumber());
        ON_CALL(*handler, PostTask).WillByDefault([](const ThreadHandler::Task &f, uint32_t) {
            if (f) {
                f();
            }
        });
        EXPECT_CALL(*handler, EnsureTask).Times(AnyNumber());
        return handler;
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_THREAD_HANDLER_H
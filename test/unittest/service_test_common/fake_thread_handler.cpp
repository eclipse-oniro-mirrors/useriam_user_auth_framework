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

#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
// Fake ThreadHandler for tests: PostTask/EnsureTask run the task inline so the
// FSM's default executor drives transitions synchronously, without linking the
// real ThreadHandler (which pulls in the hicollie/ffrt cascade).
class FakeThreadHandler : public ThreadHandler {
public:
    ~FakeThreadHandler() override = default;
    void PostTask(const Task &task) override
    {
        if (task != nullptr) {
            task();
        }
    }
    void EnsureTask(const Task &task) override
    {
        if (task != nullptr) {
            task();
        }
    }
    void Suspend() override {}
};

std::shared_ptr<ThreadHandler> ThreadHandler::GetSingleThreadInstance()
{
    static auto instance = std::make_shared<FakeThreadHandler>();
    return instance;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

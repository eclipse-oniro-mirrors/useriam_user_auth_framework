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

#include <cstdlib>
#include <memory>
#include <mutex>

namespace OHOS {
namespace UserIam {
namespace UserAuth {

// Forward declaration only: the ext part's tests inject their own concrete
// IUserRecognitionStateManager via SetUserRecognitionStateManager(), so this TU
// never needs the full type (no services/core header, no idl-generated headers).
// Mirrors fake_thread_handler.cpp — a fake definition of the services/core
// accessor so the ext-compiled controller links without pulling the real
// UserRecognitionStateManager (and its IPC / death-recipient / resident-thread
// deps) into the test binary.
class IUserRecognitionStateManager;

namespace {
struct ManagerStore {
    std::mutex mutex;
    std::shared_ptr<IUserRecognitionStateManager> instance;
};

ManagerStore &GetStore()
{
    static ManagerStore store;
    return store;
}
} // namespace

std::shared_ptr<IUserRecognitionStateManager> CreateUserRecognitionStateManager()
{
    return nullptr;
}

IUserRecognitionStateManager &GetUserRecognitionStateManager()
{
    auto &store = GetStore();
    std::shared_ptr<IUserRecognitionStateManager> manager;
    {
        std::lock_guard<std::mutex> lock(store.mutex);
        if (!store.instance) {
            store.instance = CreateUserRecognitionStateManager();
        }
        manager = store.instance;
    }
    if (manager == nullptr) {
        std::abort();
    }
    return *manager.get();
}

void SetUserRecognitionStateManager(std::shared_ptr<IUserRecognitionStateManager> manager)
{
    std::lock_guard<std::mutex> lock(GetStore().mutex);
    GetStore().instance = std::move(manager);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

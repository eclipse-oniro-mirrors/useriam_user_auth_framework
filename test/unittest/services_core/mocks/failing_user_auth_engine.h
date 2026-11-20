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
#ifndef IAM_TEST_FAILING_USER_AUTH_ENGINE_H
#define IAM_TEST_FAILING_USER_AUTH_ENGINE_H

#include "dummy_user_auth_engine.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
// Simulates an unavailable HDI: every engine call fails. This keeps the core
// modules' error paths covered without linking the real HDI implementation.
class FailingUserAuthEngine final : public DummyUserAuthEngine {
public:
    FailingUserAuthEngine() : DummyUserAuthEngine(true)
    {
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_TEST_FAILING_USER_AUTH_ENGINE_H

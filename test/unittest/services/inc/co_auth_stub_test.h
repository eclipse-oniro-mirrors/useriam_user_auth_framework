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

#ifndef IAM_CO_AUTH_STUB_TEST_H
#define IAM_CO_AUTH_STUB_TEST_H

#include <gtest/gtest.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuthStubTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CO_AUTH_STUB_TEST_H
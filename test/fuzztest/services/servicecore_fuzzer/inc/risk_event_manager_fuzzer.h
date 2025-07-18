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

#ifndef RISK_EVENT_MANAGER_FUZZ_TEST_H
#define RISK_EVENT_MANAGER_FUZZ_TEST_H

#include "parcel.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void RiskEventManagerFuzzTest(Parcel &parcel);
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // RISK_EVENT_MANAGER_FUZZ_TEST_H

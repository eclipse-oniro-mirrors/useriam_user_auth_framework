/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import LogUtils from '../common/utils/LogUtils';
import UIAbility from '@ohos.app.ability.UIAbility';
import window from '@ohos.window';

const TAG = 'MainAbility';

export default class MainAbility extends UIAbility {
  onCreate(): void {
    LogUtils.i(TAG, 'Ability onCreate');
  }

  onDestroy(): void | Promise<void> {
    LogUtils.i(TAG, 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    LogUtils.i(TAG, 'Ability onWindowStageCreate');

    windowStage.loadContent('pages/Index', (err, data) => {
      if (err.code) {
        LogUtils.e(TAG, 'Failed to load the content. Cause: %{public}s' + JSON.stringify(err) ?? '');
        return;
      }
      LogUtils.i(TAG, 'Succeeded in loading the content. Data: %{public}s' + JSON.stringify(data) ?? '');
    });
  }

  onWindowStageDestroy(): void {
    LogUtils.i(TAG, 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    LogUtils.i(TAG, 'Ability onForeground');
  }

  onBackground(): void {
    LogUtils.i(TAG, 'Ability onBackground');
  }
}

/**
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
import type UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import LogUtils from './LogUtils';

const TAG = 'WindowPrivacyUtils';

export class WindowPrivacyUtils {
  setWindowPrivacyMode(session: UIExtensionContentSession, isPrivacyMode: boolean): void {
    LogUtils.debug(TAG, 'setWindowPrivacyMode');
    try {
      session?.setWindowPrivacyMode(isPrivacyMode, (error) => {
        if (error) {
          LogUtils.error(TAG, 'setWindowPrivacyMode error');
          return;
        }
        LogUtils.debug(TAG, 'setWindowPrivacyMode success');
      });
    } catch (error) {
      LogUtils.error(TAG, 'setWindowPrivacyMode catch error: ' + error?.code);
      globalThis.session?.terminateSelf?.();
    }
  }
}

let mWindowPrivacyUtils = new WindowPrivacyUtils();

export default mWindowPrivacyUtils as WindowPrivacyUtils;

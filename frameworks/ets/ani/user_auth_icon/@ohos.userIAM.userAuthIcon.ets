/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import {
  Column,
  Component,
  Dimension,
  PropRef,
  ResourceColor,
  Row,
  State,
  SymbolGlyph,
  $r,
} from '@kit.ArkUI';
import { BusinessError } from '@ohos.base';
import hiLog from '@ohos.hilog';
import userAuth from '@ohos.userIAM.userAuth';

const DOMAIN: int = 0x0007;
const TAG: string = 'useriam_auth_icon';
const ICON_UNAVAILABLE: int = 0;
const ICON_AVAILABLE: int = 1;
const TIMEOUT_MILLISECONDS: int = 5000;
const INVALID_PARAMETERS: int = 401;
const FACE_ICON_RESOURCE: string = 'sys.symbol.face';
const FINGERPRINT_ICON_RESOURCE: string = 'sys.symbol.touchid';

/**
 * Declare UserAuthIcon, use for user authentication.
 *
 * @syscap SystemCapability.UserIAM.UserAuth.Core
 * @since 12
 */
@Component
export struct UserAuthIcon {
  /**
   * Set user auth parameter.
   *
   * @type { userAuth.AuthParam }
   * @syscap SystemCapability.UserIAM.UserAuth.Core
   * @since 12
   */
  authParam: userAuth.AuthParam = {
    challenge: new Uint8Array(),
    authType: [],
    authTrustLevel: userAuth.AuthTrustLevel.ATL1
  } as userAuth.AuthParam;
  /**
   * Set auth widget parameter.
   *
   * @type { userAuth.WidgetParam }
   * @syscap SystemCapability.UserIAM.UserAuth.Core
   * @since 12
   */
  widgetParam: userAuth.WidgetParam = {
    title: ''
  } as userAuth.WidgetParam;
  /**
   * Set the height of the icon, width and height ratio 1:1.
   *
   * @type { ?Dimension }
   * @default 64
   * @syscap SystemCapability.UserIAM.UserAuth.Core
   * @since 12
   */
  iconHeight?: Dimension = 64.0;
  /**
   * Set the color of the icon.
   *
   * @type { ?ResourceColor }
   * @default $r('sys.color.ohos_id_color_activated')
   * @syscap SystemCapability.UserIAM.UserAuth.Core
   * @since 12
   */
  @PropRef iconColor: ResourceColor = $r('sys.color.ohos_id_color_activated');
  authFlag: int = ICON_UNAVAILABLE;
  @State imageSource: string = '';
  /**
   * The authentication result code is returned through the callback.
   * If the authentication is passed, the authentication token and auth type will be returned.
   * You need to apply for permission:ohos.permission.ACCESS_BIOMETRIC to use user authentication ability.
   *
   * @param { userAuth.UserAuthResult } result - Authentication result information.
   * @syscap SystemCapability.UserIAM.UserAuth.Core
   * @since 12
   */
  onAuthResult: (result: userAuth.UserAuthResult) => void = (result: userAuth.UserAuthResult) => {
  };
  /**
   * When user click the icon, it will be returned through this callback.
   *
   * @syscap SystemCapability.UserIAM.UserAuth.Core
   * @since 12
   */
  onIconClick: () => void = () => {
  };

  private initImageSource(authTypes: userAuth.UserAuthType[], authTrustLevel: userAuth.AuthTrustLevel): void {
    if (authTypes.includes(userAuth.UserAuthType.FACE) && (!authTypes.includes(userAuth.UserAuthType.FINGERPRINT))) {
      // Handle the situation where the authTypes parameter contains face type but not contains fingerprint type.
      this.authFlag = ICON_AVAILABLE;
      this.imageSource = FACE_ICON_RESOURCE;
      return;
    }
    if ((!authTypes.includes(userAuth.UserAuthType.FACE)) && authTypes.includes(userAuth.UserAuthType.FINGERPRINT)) {
      // Handle the situation where the authTypes parameter contains fingerprint type but not contains face type.
      this.authFlag = ICON_AVAILABLE;
      this.imageSource = FINGERPRINT_ICON_RESOURCE;
      return;
    }
    if (authTypes.includes(userAuth.UserAuthType.FACE) && authTypes.includes(userAuth.UserAuthType.FINGERPRINT) &&
    authTypes.includes(userAuth.UserAuthType.PIN)) {
      // Handle the situation where the authTypes parameter contains face, fingerprint, and PIN types at the same time.
      this.handleAllAuthTypeCase(authTrustLevel);
      return;
    }
    if (authTypes.includes(userAuth.UserAuthType.FACE) && authTypes.includes(userAuth.UserAuthType.FINGERPRINT) &&
      !authTypes.includes(userAuth.UserAuthType.PIN)) {
      // Handle the situation where the authTypes parameter contains face, fingerprint, but not contains PIN types at
      // the same time.
      this.authFlag = ICON_UNAVAILABLE;
      this.info('incorrect parameters.');
      this.onAuthResult({ result: INVALID_PARAMETERS });
      this.imageSource = '';
      return;
    }
    // Default processing, includes the situation where the authTypes parameter only contains face and fingerprint
    // types or the situation where the authTypes parameter only contains PIN type.
    this.authFlag = ICON_UNAVAILABLE;
    this.info('incorrect parameters.');
    this.onAuthResult({ result: userAuth.UserAuthResultCode.TYPE_NOT_SUPPORT });
    this.imageSource = '';
    return;
  }

  private handleAllAuthTypeCase(authTrustLevel: userAuth.AuthTrustLevel): void {
    if (this.checkAuthTypeSupported(userAuth.UserAuthType.FACE, authTrustLevel)) {
      this.info('face auth available.');
      this.authFlag = ICON_AVAILABLE;
      this.imageSource = FACE_ICON_RESOURCE;
      return;
    }
    if (this.checkAuthTypeSupported(userAuth.UserAuthType.FINGERPRINT, authTrustLevel)) {
      this.info('finger auth available.');
      this.authFlag = ICON_AVAILABLE;
      this.imageSource = FINGERPRINT_ICON_RESOURCE;
      return;
    }
    this.authFlag = ICON_AVAILABLE;
    this.imageSource = FACE_ICON_RESOURCE;
    return;
  }

  private checkAuthTypeSupported(authType: userAuth.UserAuthType, authTrustLevel: userAuth.AuthTrustLevel): boolean {
    this.info(`check if it is supported, authType: ${authType} authTrustLevel: ${authTrustLevel}.`);
    try {
      userAuth.getAvailableStatus(authType, authTrustLevel);
      this.info('current auth trust level is supported.');
      return true;
    } catch (error) {
      this.error(`current auth trust level is not supported, error = ${error}.`);
      return false;
    }
  }

  private info(format: string): void {
    if (hiLog.isLoggable(DOMAIN, TAG, hiLog.LogLevel.INFO)) {
      hiLog.info(DOMAIN, TAG, format);
    }
  }

  private error(format: string): void {
    if (hiLog.isLoggable(DOMAIN, TAG, hiLog.LogLevel.ERROR)) {
      hiLog.error(DOMAIN, TAG, format);
    }
  }

  aboutToAppear(): void {
    this.info('before init image source.');
    if (this.authParam.authType === undefined || this.authParam.authTrustLevel === undefined) {
      this.authFlag = ICON_UNAVAILABLE;
      this.info('incorrect parameters.');
      this.onAuthResult({ result: INVALID_PARAMETERS });
      this.imageSource = '';
      return;
    }
    this.initImageSource(this.authParam.authType, this.authParam.authTrustLevel);
    this.info(`after init image source, imageSource = ${this.imageSource}.`);
  }

  onclick(): void {
    this.info('start handle click event.');
    if (this.onIconClick !== undefined) {
      this.info('click event has response.');
      this.onIconClick();
    }
    if (this.authFlag === ICON_AVAILABLE) {
      let timer: int | undefined;
      try {
        let userAuthInstance: userAuth.UserAuthInstance =
          userAuth.getUserAuthInstance(this.authParam, this.widgetParam);
        timer = setTimeout(() => {
          this.error('auth timeout.');
          userAuthInstance.cancel();
          this.onAuthResult({ result: userAuth.UserAuthResultCode.GENERAL_ERROR });
        }, TIMEOUT_MILLISECONDS)
        this.info('get userAuth instance success.');
        userAuthInstance.onResult({
          onResult: (result: userAuth.UserAuthResult) => {
              this.info(`userAuthInstance callback result = ${result.result}.`);
              this.onAuthResult(result);
              userAuthInstance.offResult();
          }
        });
        this.info('auth before start.');
        userAuthInstance.start();
        this.info('auth start success.');
      } catch (error) {
        if (error) {
          let code: int = (error as BusinessError).code;
          let message: string = (error as BusinessError).message;
          this.error(`auth catch error, code: ${code}, message: ${message}`);
          this.onAuthResult({ result: code });
          return;
        }
        this.error('auth error.');
        this.onAuthResult({ result: userAuth.UserAuthResultCode.GENERAL_ERROR });
      } finally {
        if (timer !== undefined) {
          clearTimeout(timer);
        }
      }
    }
    this.info('end handle click event.');
  }

  build(): void {
    Row() {
      Column() {
        SymbolGlyph($r(this.imageSource))
          .fontSize(this.iconHeight)
          .fontColor([this.iconColor])
          .onClick(() => this.onclick())
          .draggable(false)
      }
    }
  }
}

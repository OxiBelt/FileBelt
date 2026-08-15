// SPDX-License-Identifier: Apache-2.0

const NetworkChangeError = "net::ERR_NETWORK_CHANGED";
const RetryDelayMilliseconds = 250;

export async function GotoWithNetworkChangeRetry(Page, Url) {
  try {
    return await Page.goto(Url);
  } catch (ErrorValue) {
    if (!String(ErrorValue).includes(NetworkChangeError)) throw ErrorValue;
    await Page.waitForTimeout(RetryDelayMilliseconds);
    return Page.goto(Url);
  }
}

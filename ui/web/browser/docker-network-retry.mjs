// SPDX-License-Identifier: Apache-2.0

const NetworkChangeError = "net::ERR_NETWORK_CHANGED";
const RetryDelayMilliseconds = 250;
const WorkspaceFailureText = "Failed to fetch";
const WorkspaceOutcomeTimeoutMilliseconds = 15_000;

export async function GotoWithNetworkChangeRetry(Page, Url) {
  try {
    return await Page.goto(Url);
  } catch (ErrorValue) {
    if (!String(ErrorValue).includes(NetworkChangeError)) throw ErrorValue;
    await Page.waitForTimeout(RetryDelayMilliseconds);
    return Page.goto(Url);
  }
}

export async function CompleteLoginWithNetworkChangeRetry(Page, IdentityName, LoginUrl) {
  let ExactNetworkChangeObserved = false;
  let LoginReplayed = false;
  let RefreshClicked = false;
  const ObserveFailedRequest = (Request) => {
    if (Request.failure()?.errorText === NetworkChangeError) ExactNetworkChangeObserved = true;
  };
  Page.on("requestfailed", ObserveFailedRequest);
  try {
    const WorkspaceHeading = Page.getByRole("heading", { name: "My Drive" });
    const WorkspaceFailure = Page.getByRole("alert").filter({ hasText: WorkspaceFailureText });
    await Page.getByRole("link", { name: IdentityName }).click();
    try {
      await WorkspaceHeading.or(WorkspaceFailure).waitFor({
        state: "visible",
        timeout: WorkspaceOutcomeTimeoutMilliseconds,
      });
    } catch (ErrorValue) {
      if (
        ErrorValue?.name !== "TimeoutError"
        || !ExactNetworkChangeObserved
        || await WorkspaceHeading.isVisible()
        || await WorkspaceFailure.isVisible()
      ) {
        throw ErrorValue;
      }
      await Page.goto(LoginUrl);
      LoginReplayed = true;
      await Page.getByRole("link", { name: IdentityName }).click();
      await WorkspaceHeading.or(WorkspaceFailure).waitFor({
        state: "visible",
        timeout: WorkspaceOutcomeTimeoutMilliseconds,
      });
    }
    if (LoginReplayed) {
      return { ExactNetworkChangeObserved, LoginReplayed, RefreshClicked };
    }
    if (!(await WorkspaceFailure.isVisible())) {
      return { ExactNetworkChangeObserved, LoginReplayed, RefreshClicked };
    }
    await Page.waitForTimeout(RetryDelayMilliseconds);
    if (await WorkspaceHeading.isVisible() || !(await WorkspaceFailure.isVisible())) {
      return { ExactNetworkChangeObserved, LoginReplayed, RefreshClicked };
    }
    if (!ExactNetworkChangeObserved) return { ExactNetworkChangeObserved, LoginReplayed, RefreshClicked };
    await WorkspaceFailure.getByRole("button", { name: "Refresh" }).click();
    RefreshClicked = true;
    return { ExactNetworkChangeObserved, LoginReplayed, RefreshClicked };
  } finally {
    Page.off("requestfailed", ObserveFailedRequest);
  }
}

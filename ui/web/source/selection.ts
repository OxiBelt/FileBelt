// SPDX-License-Identifier: Apache-2.0

export interface SelectionState {
  readonly AnchorId: string | null;
  readonly FocusedId: string | null;
  readonly SelectedIds: ReadonlySet<string>;
}

export type SelectionAction =
  | { readonly Id: string; readonly Type: "focus" }
  | { readonly Id: string; readonly OrderedIds: readonly string[]; readonly Type: "range" }
  | { readonly Id: string; readonly Type: "replace" }
  | { readonly Id: string; readonly Type: "toggle" }
  | { readonly OrderedIds: readonly string[]; readonly Type: "all" }
  | { readonly Type: "clear" };

export const EmptySelection: SelectionState = {
  AnchorId: null,
  FocusedId: null,
  SelectedIds: new Set<string>(),
};

export function SelectionReducer(
  State: Readonly<SelectionState>,
  Action: SelectionAction,
): SelectionState {
  switch (Action.Type) {
    case "all":
      return {
        AnchorId: Action.OrderedIds[0] ?? null,
        FocusedId: State.FocusedId ?? Action.OrderedIds[0] ?? null,
        SelectedIds: new Set(Action.OrderedIds),
      };
    case "clear":
      return EmptySelection;
    case "focus":
      return { ...State, FocusedId: Action.Id };
    case "range": {
      const AnchorIndex = Math.max(0, Action.OrderedIds.indexOf(State.AnchorId ?? Action.Id));
      const TargetIndex = Math.max(0, Action.OrderedIds.indexOf(Action.Id));
      const Start = Math.min(AnchorIndex, TargetIndex);
      const End = Math.max(AnchorIndex, TargetIndex);
      return {
        ...State,
        FocusedId: Action.Id,
        SelectedIds: new Set(Action.OrderedIds.slice(Start, End + 1)),
      };
    }
    case "replace":
      return { AnchorId: Action.Id, FocusedId: Action.Id, SelectedIds: new Set([Action.Id]) };
    case "toggle": {
      const SelectedIds = new Set(State.SelectedIds);
      if (SelectedIds.has(Action.Id)) SelectedIds.delete(Action.Id);
      else SelectedIds.add(Action.Id);
      return { AnchorId: Action.Id, FocusedId: Action.Id, SelectedIds };
    }
  }
  return State;
}

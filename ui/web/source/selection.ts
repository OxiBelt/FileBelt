// SPDX-License-Identifier: Apache-2.0

export interface SelectionState {
  anchorId: string | null;
  focusedId: string | null;
  selectedIds: ReadonlySet<string>;
}

export type SelectionAction =
  | { id: string; type: "focus" }
  | { id: string; orderedIds: readonly string[]; type: "range" }
  | { id: string; type: "replace" }
  | { id: string; type: "toggle" }
  | { orderedIds: readonly string[]; type: "all" }
  | { type: "clear" };

export const emptySelection: SelectionState = {
  anchorId: null,
  focusedId: null,
  selectedIds: new Set<string>(),
};

export function selectionReducer(state: SelectionState, action: SelectionAction): SelectionState {
  switch (action.type) {
    case "all":
      return {
        anchorId: action.orderedIds[0] ?? null,
        focusedId: state.focusedId ?? action.orderedIds[0] ?? null,
        selectedIds: new Set(action.orderedIds),
      };
    case "clear":
      return emptySelection;
    case "focus":
      return { ...state, focusedId: action.id };
    case "range": {
      const anchorIndex = Math.max(0, action.orderedIds.indexOf(state.anchorId ?? action.id));
      const targetIndex = Math.max(0, action.orderedIds.indexOf(action.id));
      const start = Math.min(anchorIndex, targetIndex);
      const end = Math.max(anchorIndex, targetIndex);
      return { ...state, focusedId: action.id, selectedIds: new Set(action.orderedIds.slice(start, end + 1)) };
    }
    case "replace":
      return { anchorId: action.id, focusedId: action.id, selectedIds: new Set([action.id]) };
    case "toggle": {
      const selectedIds = new Set(state.selectedIds);
      if (selectedIds.has(action.id)) selectedIds.delete(action.id);
      else selectedIds.add(action.id);
      return { anchorId: action.id, focusedId: action.id, selectedIds };
    }
  }
}

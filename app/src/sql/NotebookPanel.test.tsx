import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { notebooks as notebooksFixture, savedQuery } from "../test/fixtures";
import type { NotebookSummary } from "../api";

vi.mock("../api", async (orig) => ({
  ...(await orig<typeof import("../api")>()),
  notebookList: vi.fn(),
  notebookQuery: vi.fn(),
  notebookCreate: vi.fn(),
  notebookAddQuery: vi.fn(),
  notebookRename: vi.fn(),
  notebookSaveNew: vi.fn(),
  notebookDelete: vi.fn(),
  notebookDeleteQuery: vi.fn(),
  notebookMoveQuery: vi.fn(),
  notebookCaseValues: vi.fn(),
  notebookExport: vi.fn(),
  notebookImport: vi.fn(),
  sqlRun: vi.fn(),
}));
vi.mock("../dialog", () => ({ save: vi.fn(), open: vi.fn() }));

import * as api from "../api";
import * as dialog from "../dialog";
import { DataVersionContext } from "../shell/nav";
import NotebookPanel from "./NotebookPanel";

const m = {
  list: vi.mocked(api.notebookList),
  query: vi.mocked(api.notebookQuery),
  create: vi.mocked(api.notebookCreate),
  add: vi.mocked(api.notebookAddQuery),
  rename: vi.mocked(api.notebookRename),
  saveNew: vi.mocked(api.notebookSaveNew),
  del: vi.mocked(api.notebookDelete),
  delQuery: vi.mocked(api.notebookDeleteQuery),
  move: vi.mocked(api.notebookMoveQuery),
  run: vi.mocked(api.sqlRun),
  caseValues: vi.mocked(api.notebookCaseValues),
  exportNb: vi.mocked(api.notebookExport),
  importNb: vi.mocked(api.notebookImport),
  save: vi.mocked(dialog.save),
  open: vi.mocked(dialog.open),
};
let list: NotebookSummary[];
const onLoad = vi.fn();

beforeEach(() => {
  cleanup();
  for (const f of Object.values(m)) f.mockReset();
  onLoad.mockReset();
  list = notebooksFixture();
  m.list.mockImplementation(async () => list);
  m.query.mockImplementation(async (nb, q) => savedQuery(nb === "Built-in" ? "builtin" : nb, q));
  m.create.mockResolvedValue("nb2");
  m.add.mockResolvedValue("q9");
  m.saveNew.mockResolvedValue({ notebook_id: "nb2", query_id: "q9" });
  for (const f of [m.rename, m.del, m.delQuery, m.move, m.exportNb]) f.mockResolvedValue(null);
  m.caseValues.mockResolvedValue([]);
  m.save.mockResolvedValue("/out/Triage.sql");
  m.open.mockResolvedValue("/in/shared.sql");
  m.importNb.mockResolvedValue("nb3");
});

function setup(editorText = "", version = 0) {
  const user = userEvent.setup();
  const ui = (text: string, v: number) => (
    <DataVersionContext.Provider value={v}>
      <NotebookPanel editorText={text} onLoad={onLoad} />
    </DataVersionContext.Provider>
  );
  const r = render(ui(editorText, version));
  return { user, rerender: (text: string, v = version) => r.rerender(ui(text, v)) };
}

const picker = () => screen.getByRole("combobox", { name: "Notebook" });
const row = (title: RegExp) => screen.findByRole("button", { name: title });

describe("NotebookPanel", () => {
  it("shows_the_builtin_first_with_placeholder_chips", async () => {
    setup();
    const r = await row(/Sign-ins per account/);
    expect(within(r).getByText("[account]")).toBeTruthy();
    expect((picker() as HTMLSelectElement).value).toBe("builtin");
    const opts = within(picker()).getAllByRole("option").map((o) => o.textContent);
    expect(opts.slice(0, 2)).toEqual(["Built-in", "Triage"]);
  });

  it("clicking_a_query_loads_without_running", async () => {
    const { user } = setup();
    await user.click(await row(/Every operation/));
    await waitFor(() => expect(onLoad).toHaveBeenCalledWith("-- Every operation by workload, rarest first\nSELECT 1"));
    expect(m.run).not.toHaveBeenCalled();
  });

  it("loading_over_unsaved_text_asks_first", async () => {
    const { user } = setup("SELECT 9");
    await user.click(await row(/Every operation/));
    await screen.findByText("Replace the editor's text?");
    expect(onLoad).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Keep editing" }));
    expect(screen.queryByText("Replace the editor's text?")).toBeNull();
    expect(onLoad).not.toHaveBeenCalled();
    await user.click(await row(/Every operation/));
    await user.click(await screen.findByRole("button", { name: "Replace" }));
    expect(onLoad).toHaveBeenCalledTimes(1);
  });

  it("marks_the_loaded_query_edited_and_reloads_it_without_asking", async () => {
    const { user, rerender } = setup();
    await user.click(await row(/Every operation/));
    await waitFor(() => expect(onLoad).toHaveBeenCalledTimes(1));
    rerender("-- Every operation by workload, rarest first\nSELECT 1");
    expect(screen.queryByText("edited")).toBeNull();
    rerender("-- Every operation by workload, rarest first\nSELECT 2");
    expect(await screen.findByText("edited")).toBeTruthy();
    // The editor holds the loaded query (edited): loading another asks, as for any unsaved text.
    await user.click(await row(/Sign-ins per account/));
    expect(await screen.findByText("Replace the editor's text?")).toBeTruthy();
  });

  it("save_as_adds_to_a_case_notebook_never_the_builtin", async () => {
    const { user } = setup("SELECT 7");
    await user.click(await screen.findByRole("button", { name: "Save as…" }));
    const target = screen.getByRole("combobox", { name: "Save to" });
    const names = within(target).getAllByRole("option").map((o) => o.textContent);
    expect(names).not.toContain("Built-in");
    expect(names).toEqual(["Triage", "New notebook…"]);
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(m.add).toHaveBeenCalledWith("nb1", "SELECT 7"));
    expect(m.create).not.toHaveBeenCalled();
    await waitFor(() => expect((picker() as HTMLSelectElement).value).toBe("nb1"));
  });

  it("save_as_into_a_new_notebook_is_one_write", async () => {
    const { user } = setup("SELECT 7");
    await user.click(await screen.findByRole("button", { name: "Save as…" }));
    await user.selectOptions(screen.getByRole("combobox", { name: "Save to" }), "New notebook…");
    await user.type(screen.getByRole("textbox", { name: "New notebook name" }), "Mine");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(m.saveNew).toHaveBeenCalledWith("Mine", "SELECT 7"));
    expect(m.create).not.toHaveBeenCalled();
    expect(m.add).not.toHaveBeenCalled();
  });

  it("save_as_is_disabled_for_an_empty_editor", async () => {
    setup("  ");
    expect(((await screen.findByRole("button", { name: "Save as…" })) as HTMLButtonElement).disabled).toBe(true);
  });

  it("builtin_rows_have_no_edit_controls", async () => {
    setup();
    await row(/Sign-ins per account/);
    expect(screen.queryByRole("button", { name: /^Delete/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Move/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Rename notebook" })).toBeNull();
  });

  it("case_rows_can_move_and_delete_with_inline_confirm", async () => {
    const { user } = setup();
    await row(/Sign-ins per account/);
    await user.selectOptions(picker(), "nb1");
    await row(/^Hosts/);
    expect(screen.queryByRole("button", { name: 'Move "Hosts" up' })).toBeNull();
    await user.click(screen.getByRole("button", { name: 'Move "Hosts" down' }));
    expect(m.move).toHaveBeenCalledWith("q1", 2);
    await user.click(screen.getByRole("button", { name: 'Move "Third" up' }));
    expect(m.move).toHaveBeenCalledWith("q3", 2);
    await user.click(screen.getByRole("button", { name: 'Delete "Hosts"' }));
    await screen.findByText('Delete "Hosts"?');
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(m.delQuery).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: 'Delete "Hosts"' }));
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(m.delQuery).toHaveBeenCalledWith("q1"));
  });

  it("the_text_of_a_deleted_loaded_query_is_unsaved_work", async () => {
    const { user, rerender } = setup();
    await row(/Sign-ins per account/);
    await user.selectOptions(picker(), "nb1");
    await user.click(await row(/^Hosts/));
    await waitFor(() => expect(onLoad).toHaveBeenCalledTimes(1));
    const text = onLoad.mock.calls[0][0] as string;
    rerender(text);
    list = notebooksFixture();
    list[1].queries = list[1].queries.filter((q) => q.query_id !== "q1");
    await user.click(screen.getByRole("button", { name: 'Delete "Hosts"' }));
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: /^Hosts/ })).toBeNull());
    // The editor's text is now saved nowhere: loading another query asks first.
    await user.click(await row(/^Third/));
    expect(await screen.findByText("Replace the editor's text?")).toBeTruthy();
    expect(onLoad).toHaveBeenCalledTimes(1);
  });

  it("a_deleted_loaded_query_is_unsaved_before_the_list_reloads", async () => {
    const { user, rerender } = setup();
    await row(/Sign-ins per account/);
    await user.selectOptions(picker(), "nb1");
    await user.click(await row(/^Hosts/));
    await waitFor(() => expect(onLoad).toHaveBeenCalledTimes(1));
    rerender(onLoad.mock.calls[0][0] as string);
    m.list.mockImplementation(() => new Promise(() => {}));
    await user.click(screen.getByRole("button", { name: 'Delete "Hosts"' }));
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(m.delQuery).toHaveBeenCalledWith("q1"));
    await user.click(await row(/^Third/));
    expect(await screen.findByText("Replace the editor's text?")).toBeTruthy();
    expect(onLoad).toHaveBeenCalledTimes(1);
  });

  it("deleting_the_loaded_querys_notebook_makes_its_text_unsaved", async () => {
    const { user, rerender } = setup();
    await row(/Sign-ins per account/);
    await user.selectOptions(picker(), "nb1");
    await user.click(await row(/^Hosts/));
    await waitFor(() => expect(onLoad).toHaveBeenCalledTimes(1));
    rerender(onLoad.mock.calls[0][0] as string);
    m.list.mockImplementation(() => new Promise(() => {}));
    await user.click(screen.getByRole("button", { name: "Delete notebook" }));
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(m.del).toHaveBeenCalledWith("nb1"));
    await user.selectOptions(picker(), "builtin");
    await user.click(await row(/Every operation/));
    expect(await screen.findByText("Replace the editor's text?")).toBeTruthy();
    expect(onLoad).toHaveBeenCalledTimes(1);
  });

  it("a_waiting_replace_is_dropped_when_its_query_vanishes", async () => {
    const { user, rerender } = setup("SELECT 9");
    await row(/Sign-ins per account/);
    await user.selectOptions(picker(), "nb1");
    await user.click(await row(/^Hosts/));
    await screen.findByText("Replace the editor's text?");
    list = notebooksFixture();
    list[1].queries = list[1].queries.filter((q) => q.query_id !== "q1");
    rerender("SELECT 9", 1);
    await waitFor(() => expect(screen.queryByText("Replace the editor's text?")).toBeNull());
    expect(onLoad).not.toHaveBeenCalled();
  });

  it("choosing_a_notebook_while_creating_one_leaves_the_new_notebook_form", async () => {
    const { user } = setup();
    await row(/Sign-ins per account/);
    await user.selectOptions(picker(), "__new__");
    expect(screen.getByRole("textbox", { name: "New notebook name" })).toBeTruthy();
    await user.selectOptions(picker(), "nb1");
    expect((picker() as HTMLSelectElement).value).toBe("nb1");
    expect(screen.queryByRole("textbox", { name: "New notebook name" })).toBeNull();
    expect(await row(/^Hosts/)).toBeTruthy();
  });

  it("a_case_notebook_can_be_renamed_and_deleted", async () => {
    const { user } = setup();
    await row(/Sign-ins per account/);
    await user.selectOptions(picker(), "nb1");
    await user.click(await screen.findByRole("button", { name: "Rename notebook" }));
    const name = screen.getByRole("textbox", { name: "Notebook name" });
    await user.clear(name);
    await user.type(name, "Renamed");
    await user.click(screen.getByRole("button", { name: "Rename" }));
    await waitFor(() => expect(m.rename).toHaveBeenCalledWith("nb1", "Renamed"));
    await user.click(screen.getByRole("button", { name: "Delete notebook" }));
    await screen.findByText('Delete notebook "Triage" and its 3 queries?');
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(m.del).toHaveBeenCalledWith("nb1"));
  });

  it("an_agent_add_refreshes_the_list_and_keeps_the_editor", async () => {
    const { user, rerender } = setup("SELECT 5");
    await row(/Sign-ins per account/);
    await user.selectOptions(picker(), "nb1");
    await row(/^Hosts/);
    list = notebooksFixture();
    list[1].queries.push({ ...list[1].queries[1], query_id: "q4", position: 4, title: "New from agent" });
    rerender("SELECT 5", 1);
    const r = await row(/^New from agent/);
    expect(within(r.closest("li")!).getByText("by claude")).toBeTruthy();
    expect((picker() as HTMLSelectElement).value).toBe("nb1");
    expect(onLoad).not.toHaveBeenCalled();
  });

  it("falls_back_to_the_builtin_when_the_chosen_notebook_vanishes", async () => {
    const { user, rerender } = setup();
    await row(/Sign-ins per account/);
    await user.selectOptions(picker(), "nb1");
    await row(/^Hosts/);
    list = notebooksFixture().slice(0, 1);
    rerender("", 1);
    await waitFor(() => expect((picker() as HTMLSelectElement).value).toBe("builtin"));
  });

  it("a_list_load_error_clears_when_the_list_next_loads", async () => {
    m.list.mockRejectedValueOnce({ kind: "internal", message: "the case is busy" });
    const { rerender } = setup();
    expect((await screen.findByRole("alert")).textContent).toContain("the case is busy");
    rerender("", 1);
    await row(/Sign-ins per account/);
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  });

  it("a_list_load_error_clears_when_an_import_loads_the_list", async () => {
    m.list.mockRejectedValueOnce({ kind: "internal", message: "the case is busy" });
    const { user } = setup();
    await screen.findByRole("alert");
    list = notebooksFixture();
    list.push({ notebook_id: "nb3", name: "Shared", builtin: false, queries: [] });
    await user.click(screen.getByRole("button", { name: "Import…" }));
    await screen.findByText("Imported as Shared");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("a_refused_write_stays_shown_when_the_list_reloads", async () => {
    m.add.mockRejectedValue({ kind: "read_only", message: "the case is read-only (mock)" });
    const { user, rerender } = setup("SELECT 7");
    await user.click(await screen.findByRole("button", { name: "Save as…" }));
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByRole("alert");
    rerender("SELECT 7", 1);
    await waitFor(() => expect(m.list).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("alert").textContent).toContain("the case is read-only (mock)");
  });

  it("shows_a_refused_write_as_the_backend_words_it", async () => {
    m.add.mockRejectedValue({ kind: "read_only", message: "the case is read-only (mock)" });
    const { user } = setup("SELECT 7");
    await user.click(await screen.findByRole("button", { name: "Save as…" }));
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect((await screen.findByRole("alert")).textContent).toContain("the case is read-only (mock)");
  });

  describe("export and import", () => {
    it("export_without_case_values_goes_straight_to_the_save_dialog", async () => {
      const { user } = setup();
      await row(/Sign-ins per account/);
      await user.selectOptions(picker(), "nb1");
      await user.click(screen.getByRole("button", { name: "Export…" }));
      await waitFor(() => expect(m.exportNb).toHaveBeenCalledWith("nb1", "/out/Triage.sql", []));
      expect(m.caseValues).toHaveBeenCalledWith("nb1");
      expect(m.save).toHaveBeenCalledWith({ defaultPath: "Triage.sql", filters: [{ name: "SQL notebook", extensions: ["sql"] }] });
      expect(await screen.findByText("Exported Triage to /out/Triage.sql")).toBeTruthy();
    });

    it("export_with_case_values_lists_them_and_waits", async () => {
      m.caseValues.mockResolvedValue([{ query_id: "q1", title: "Hosts", values: ["203.0.113.7", "contoso.example"] }]);
      const { user } = setup();
      await row(/Sign-ins per account/);
      await user.selectOptions(picker(), "nb1");
      await user.click(screen.getByRole("button", { name: "Export…" }));
      await screen.findByText("These queries contain values from this case:");
      expect(screen.getByText("Hosts: 203.0.113.7, contoso.example")).toBeTruthy();
      expect(m.save).not.toHaveBeenCalled();
      await user.click(screen.getByRole("button", { name: "Cancel" }));
      expect(m.save).not.toHaveBeenCalled();
      expect(m.exportNb).not.toHaveBeenCalled();
      await user.click(screen.getByRole("button", { name: "Export…" }));
      await user.click(await screen.findByRole("button", { name: "Export anyway" }));
      await waitFor(() => expect(m.exportNb).toHaveBeenCalledWith("nb1", "/out/Triage.sql", ["203.0.113.7", "contoso.example"]));
    });

    it("a_cancelled_save_dialog_writes_nothing", async () => {
      m.save.mockResolvedValue(null);
      const { user } = setup();
      await user.click(await screen.findByRole("button", { name: "Export…" }));
      await waitFor(() => expect(m.save).toHaveBeenCalled());
      expect(m.exportNb).not.toHaveBeenCalled();
    });

    it("import_chooses_the_new_notebook", async () => {
      const { user } = setup();
      await row(/Sign-ins per account/);
      list = notebooksFixture();
      list.push({ notebook_id: "nb3", name: "Shared", builtin: false, queries: [] });
      await user.click(screen.getByRole("button", { name: "Import…" }));
      await waitFor(() => expect(m.importNb).toHaveBeenCalledWith("/in/shared.sql"));
      expect(m.open).toHaveBeenCalledWith({ filters: [{ name: "SQL notebook", extensions: ["sql"] }] });
      await waitFor(() => expect((picker() as HTMLSelectElement).value).toBe("nb3"));
      expect(await screen.findByText("Imported as Shared")).toBeTruthy();
    });

    it("a_refused_import_shows_the_reason", async () => {
      m.importNb.mockRejectedValue({ kind: "decision", message: "line 3: a query must not be empty" });
      const { user } = setup();
      await user.click(await screen.findByRole("button", { name: "Import…" }));
      expect((await screen.findByRole("alert")).textContent).toContain("line 3: a query must not be empty");
    });
  });

  describe("races", () => {
    it("a_loaded_query_edited_to_blank_is_still_unsaved_work", async () => {
      const { user, rerender } = setup();
      await user.click(await row(/Every operation/));
      await waitFor(() => expect(onLoad).toHaveBeenCalledTimes(1));
      rerender("   ");
      await user.click(await row(/Sign-ins per account/));
      expect(await screen.findByText("Replace the editor's text?")).toBeTruthy();
      expect(onLoad).toHaveBeenCalledTimes(1);
    });

    it("typing_while_a_query_loads_asks_before_replacing", async () => {
      let finish: (q: api.SavedQuery) => void = () => {};
      m.query.mockImplementation(() => new Promise((rs) => (finish = rs)));
      const { user, rerender } = setup("");
      await user.click(await row(/Every operation/));
      rerender("SELECT typed meanwhile");
      finish(savedQuery("builtin", "builtin:operations-by-workload"));
      expect(await screen.findByText("Replace the editor's text?")).toBeTruthy();
      expect(onLoad).not.toHaveBeenCalled();
    });

    it("only_the_newest_pick_loads", async () => {
      const finish: ((q: api.SavedQuery) => void)[] = [];
      m.query.mockImplementation(() => new Promise((rs) => finish.push(rs)));
      const { user } = setup("");
      await user.click(await row(/Every operation/));
      await user.click(await row(/Sign-ins per account/));
      finish[1](savedQuery("builtin", "builtin:signins-by-country"));
      finish[0](savedQuery("builtin", "builtin:operations-by-workload"));
      await waitFor(() => expect(onLoad).toHaveBeenCalledTimes(1));
      expect(onLoad.mock.calls[0][0]).toContain("Sign-ins per account");
    });

    it("an_export_warning_is_dropped_when_the_notebook_changes", async () => {
      m.caseValues.mockResolvedValue([{ query_id: "q1", title: "Hosts", values: ["203.0.113.7"] }]);
      const { user } = setup();
      await row(/Sign-ins per account/);
      await user.selectOptions(picker(), "nb1");
      await user.click(screen.getByRole("button", { name: "Export…" }));
      await screen.findByText("These queries contain values from this case:");
      await user.selectOptions(picker(), "builtin");
      expect(screen.queryByRole("button", { name: "Export anyway" })).toBeNull();
      expect(m.save).not.toHaveBeenCalled();
    });

    it("a_late_export_check_for_another_notebook_is_ignored", async () => {
      let finish: (h: api.CaseValueHit[]) => void = () => {};
      m.caseValues.mockImplementation(() => new Promise((rs) => (finish = rs)));
      const { user } = setup();
      await row(/Sign-ins per account/);
      await user.selectOptions(picker(), "nb1");
      await user.click(screen.getByRole("button", { name: "Export…" }));
      await user.selectOptions(picker(), "builtin");
      finish([{ query_id: "q1", title: "Hosts", values: ["203.0.113.7"] }]);
      await new Promise((r) => setTimeout(r, 20));
      expect(screen.queryByText("These queries contain values from this case:")).toBeNull();
      expect(m.save).not.toHaveBeenCalled();
    });

    it("an_export_warning_is_dropped_when_the_case_changes", async () => {
      m.caseValues.mockResolvedValue([{ query_id: "q1", title: "Hosts", values: ["203.0.113.7"] }]);
      const { user, rerender } = setup();
      await row(/Sign-ins per account/);
      await user.selectOptions(picker(), "nb1");
      await user.click(screen.getByRole("button", { name: "Export…" }));
      await screen.findByText("These queries contain values from this case:");
      rerender("", 1);
      await waitFor(() => expect(screen.queryByRole("button", { name: "Export anyway" })).toBeNull());
    });
  });
});

// SweepR audit report interactivity. No network access; never uses innerHTML with data.
(function () {
  "use strict";
  var doc = document;
  function $$(sel, root) { return Array.prototype.slice.call((root || doc).querySelectorAll(sel)); }

  // ---- sortable tables -------------------------------------------------------------------
  function cellKey(row, idx) {
    var cell = row.children[idx];
    if (!cell) return "";
    return cell.hasAttribute("data-v") ? cell.getAttribute("data-v") : cell.textContent.trim();
  }
  function compare(a, b, numeric) {
    if (numeric) {
      var x = parseFloat(a), y = parseFloat(b);
      if (isNaN(x)) x = -Infinity;
      if (isNaN(y)) y = -Infinity;
      return x - y;
    }
    return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
  }
  $$("table.sortable").forEach(function (table) {
    var grouped = table.classList.contains("grouped");
    $$("thead th", table).forEach(function (th, idx) {
      var btn = th.querySelector("button");
      if (!btn) return;
      btn.addEventListener("click", function () {
        var dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
        $$("thead th", table).forEach(function (o) { o.removeAttribute("aria-sort"); });
        th.setAttribute("aria-sort", dir);
        var numeric = th.getAttribute("data-type") === "num";
        var sign = dir === "ascending" ? 1 : -1;
        if (grouped) {
          // One <tbody> per finding: sort the groups by their first row.
          var groups = $$("tbody", table);
          groups.sort(function (g1, g2) {
            return sign * compare(cellKey(g1.rows[0], idx), cellKey(g2.rows[0], idx), numeric);
          });
          groups.forEach(function (g) { table.appendChild(g); });
        } else {
          var body = table.tBodies[0];
          var rows = Array.prototype.slice.call(body.rows);
          rows.sort(function (r1, r2) { return sign * compare(cellKey(r1, idx), cellKey(r2, idx), numeric); });
          rows.forEach(function (r) { body.appendChild(r); });
        }
      });
    });
  });

  // ---- findings: expand / filter ----------------------------------------------------------
  function setExpanded(group, open) {
    var btn = group.querySelector(".toggle");
    var detail = group.querySelector(".f-detail");
    if (!btn || !detail) return;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    detail.hidden = !open;
  }
  $$(".f-group").forEach(function (g) {
    var btn = g.querySelector(".toggle");
    if (btn) btn.addEventListener("click", function () {
      setExpanded(g, btn.getAttribute("aria-expanded") !== "true");
    });
    var title = g.querySelector(".f-title");
    if (title) title.addEventListener("click", function () {
      setExpanded(g, btn.getAttribute("aria-expanded") !== "true");
    });
  });
  function expandAll(open) { $$(".f-group").forEach(function (g) { setExpanded(g, open); }); }
  $$("[data-action=expand]").forEach(function (b) { b.addEventListener("click", function () { expandAll(true); }); });
  $$("[data-action=collapse]").forEach(function (b) { b.addEventListener("click", function () { expandAll(false); }); });

  var findingSearch = doc.getElementById("finding-search");
  function filterFindings() {
    var active = $$(".sev-filter").filter(function (c) { return c.getAttribute("aria-pressed") === "true"; })
      .map(function (c) { return c.getAttribute("data-sev"); });
    var q = findingSearch ? findingSearch.value.trim().toLowerCase() : "";
    var shown = 0, groups = $$(".f-group");
    groups.forEach(function (g) {
      var ok = active.indexOf(g.getAttribute("data-sev")) >= 0 && (!q || g.textContent.toLowerCase().indexOf(q) >= 0);
      g.classList.toggle("filtered-out", !ok);
      if (ok) shown++;
    });
    var c = doc.getElementById("finding-count");
    if (c) c.textContent = shown + " of " + groups.length + " findings";
  }
  $$(".sev-filter").forEach(function (chip) {
    chip.addEventListener("click", function () {
      chip.setAttribute("aria-pressed", chip.getAttribute("aria-pressed") === "true" ? "false" : "true");
      filterFindings();
    });
  });
  if (findingSearch) findingSearch.addEventListener("input", filterFindings);

  // ---- inventory: search / column toggles -------------------------------------------------
  var inv = doc.getElementById("inventory-table");
  var invSearch = doc.getElementById("inventory-search");
  function filterInventory() {
    if (!inv) return;
    var q = invSearch.value.trim().toLowerCase();
    var rows = Array.prototype.slice.call(inv.tBodies[0].rows), shown = 0;
    rows.forEach(function (r) {
      var ok = !q || r.textContent.toLowerCase().indexOf(q) >= 0;
      r.classList.toggle("filtered-out", !ok);
      if (ok) shown++;
    });
    var c = doc.getElementById("inventory-count");
    if (c) c.textContent = shown + " of " + rows.length + " devices";
  }
  if (invSearch) invSearch.addEventListener("input", filterInventory);
  $$(".col-toggle").forEach(function (cb) {
    var table = doc.getElementById(cb.getAttribute("data-table"));
    var cls = "hide-c" + cb.getAttribute("data-col");
    function apply() { if (table) table.classList.toggle(cls, !cb.checked); }
    cb.addEventListener("change", apply);
    apply();
  });

  // ---- header actions ---------------------------------------------------------------------
  $$("[data-action=print]").forEach(function (b) { b.addEventListener("click", function () { window.print(); }); });
  $$("[data-action=theme]").forEach(function (b) {
    b.addEventListener("click", function () {
      var root = doc.documentElement;
      var dark = root.getAttribute("data-theme")
        ? root.getAttribute("data-theme") === "dark"
        : window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.setAttribute("data-theme", dark ? "light" : "dark");
    });
  });
  $$("[data-action=json]").forEach(function (b) {
    b.addEventListener("click", function () {
      var data = doc.getElementById("report-data");
      if (!data) return;
      var blob = new Blob([data.textContent], { type: "application/json" });
      var a = doc.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "sweepr-audit.json";
      doc.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
    });
  });

  // Print shows every finding expanded (CSS) and restores afterwards.
  filterFindings();
  filterInventory();
})();

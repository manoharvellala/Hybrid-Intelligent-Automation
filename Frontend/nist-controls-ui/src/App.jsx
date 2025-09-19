import React, { useEffect, useMemo, useState } from 'react';

// Zero-dependency React UI for the NIST Controls API.
// - No shadcn, no framer-motion, no icon libs
// - Uses native <dialog> for modals
// - Works with a stock Vite React app
// - Styling via plain CSS classes defined in App.css (see bottom of file for CSS)

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:7654';

// ---- helpers ----
function safeStringify(obj) {
  try {
    return JSON.stringify(obj ?? {}, null, 2);
  } catch {
    return '{}';
  }
}
function safeParseJson(txt) {
  if (!txt || !txt.trim()) return {};
  try {
    return JSON.parse(txt);
  } catch {
    throw new Error('Invalid JSON in Extra');
  }
}

// ---- text shrink helpers ----
const TITLE_MAX = 36; // visible length for the title
const SUBTEXT_MAX = 90; // visible length for the subtitle (narrative/info)

function shrinkText(str = '', max = 36) {
  const s = String(str ?? '').trim();
  if (!s) return '';
  if (s.length <= max) return s;
  const slice = s.slice(0, max - 1);
  const lastSpace = slice.lastIndexOf(' ');
  if (lastSpace > Math.floor(max * 0.6)) {
    return slice.slice(0, lastSpace) + '…';
  }
  return slice + '…';
}

function StatusPill({ value, kind }) {
  const cls = useMemo(() => {
    const v = (value || '').toLowerCase();
    if (kind === 'compliance') {
      if (v.includes('non') || v.includes('fail')) return 'pill pill-red';
      if (v.includes('partial') || v.includes('in')) return 'pill pill-amber';
      if (v.includes('compliant') || v.includes('pass'))
        return 'pill pill-green';
    }
    if (kind === 'impl') {
      if (v.includes('planned')) return 'pill pill-gray';
      if (v.includes('in-progress')) return 'pill pill-indigo';
      if (v.includes('implemented') || v.includes('complete'))
        return 'pill pill-emerald';
    }
    return 'pill pill-gray';
  }, [value, kind]);
  return <span className={cls}>{value || '—'}</span>;
}

export default function App() {
  const [q, setQ] = useState('');
  const [compliance, setCompliance] = useState('');
  const [impl, setImpl] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refreshTick, setRefreshTick] = useState(0);

  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [showDetails, setShowDetails] = useState(false);
  const [detailRow, setDetailRow] = useState(null);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  async function fetchList() {
    setLoading(true);
    setError('');
    try {
      const url = new URL(`${API_BASE}/controls`);
      url.searchParams.set('page', String(page));
      url.searchParams.set('page_size', String(pageSize));
      if (q) url.searchParams.set('q', q);
      if (compliance) url.searchParams.set('compliance_status', compliance);
      if (impl) url.searchParams.set('implementation_status', impl);
      const res = await fetch(url);
      if (!res.ok) throw new Error(await res.text());
      const json = await res.json();
      setRows(json.items || []);
      setTotal(json.total || 0);
    } catch (e) {
      setError(e.message || 'Failed to load');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchList(); /* eslint-disable-next-line */
  }, [page, pageSize, compliance, impl, refreshTick]);

  function onSearch(e) {
    e?.preventDefault?.();
    setPage(1);
    fetchList();
  }

  function openCreate() {
    setEditing(null);
    setShowForm(true);
  }
  function openEdit(row) {
    setEditing(row);
    setShowForm(true);
  }
  function openDetails(row) {
    setDetailRow(row);
    setShowDetails(true);
  }

  async function doDelete(acronym) {
    if (!confirm(`Delete ${acronym}?`)) return;
    try {
      const res = await fetch(
        `${API_BASE}/controls/${encodeURIComponent(acronym)}`,
        { method: 'DELETE' }
      );
      if (!res.ok) throw new Error(await res.text());
      setRefreshTick((t) => t + 1);
    } catch (e) {
      alert(e.message || 'Delete failed');
    }
  }

  return (
    <div className='page'>
      <header className='topbar'>
        <div>
          <h1>NIST SP 800-53 Controls</h1>
          <div className='sub'>API: {API_BASE}/controls</div>
        </div>
        <div className='row gap'>
          <button className='btn' onClick={openCreate}>
            ＋ New Control
          </button>
          <button
            className='btn btn-outline'
            onClick={() => setRefreshTick((t) => t + 1)}
          >
            ⟳ Refresh
          </button>
        </div>
      </header>

      <section className='card'>
        <h2 className='card-title'>Filters</h2>
        <form className='filters' onSubmit={onSearch}>
          <div className='field grow'>
            <label>Search</label>
            <div className='row'>
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder='acronym, title, narrative, …'
              />
              <button className='btn btn-secondary' type='submit'>
                Search
              </button>
            </div>
          </div>
          <div className='field'>
            <label>Compliance</label>
            <select
              value={compliance}
              onChange={(e) => setCompliance(e.target.value)}
            >
              <option value=''>Any</option>
              <option value='compliant'>Compliant</option>
              <option value='non-compliant'>Non-compliant</option>
              <option value='partial'>Partial</option>
            </select>
          </div>
          <div className='field'>
            <label>Implementation</label>
            <select value={impl} onChange={(e) => setImpl(e.target.value)}>
              <option value=''>Any</option>
              <option value='planned'>Planned</option>
              <option value='in-progress'>In-Progress</option>
              <option value='implemented'>Implemented</option>
            </select>
          </div>
          <div className='field'>
            <label>Page Size</label>
            <select
              value={String(pageSize)}
              onChange={(e) => setPageSize(Number(e.target.value))}
            >
              {[10, 20, 50, 100, 200].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
          <div className='field'>
            <label>&nbsp;</label>
            <button
              type='button'
              className='btn btn-ghost'
              onClick={() => {
                setQ('');
                setCompliance('');
                setImpl('');
                setPage(1);
                setPageSize(20);
                setRefreshTick((t) => t + 1);
              }}
            >
              Clear
            </button>
          </div>
        </form>
      </section>

      <section className='card'>
        <div className='card-title'>Results ({total})</div>
        {error && <div className='alert alert-red'>{error}</div>}
        <div className='table-wrap'>
          <table className='table'>
            <thead>
              <tr>
                <th className='w-20'>Control</th>
                <th className='title'>Title</th>
                <th className='w-28'>Compliance</th>
                <th className='w-32'>Implementation</th>
                <th className='w-32'>Target Date</th>
                <th className='w-36 right'>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} className='muted center p-24'>
                    Loading…
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className='muted center p-24'>
                    No results
                  </td>
                </tr>
              ) : (
                rows.map((r) => {
                  const titleFull = r.control_title || '—';
                  const titleShort = shrinkText(titleFull, TITLE_MAX);
                  const subFull =
                    r.implementation_narrative || r.control_information || '';
                  const subShort = shrinkText(subFull, SUBTEXT_MAX);

                  return (
                    <tr key={r.control_acronym} className='hover'>
                      <td>
                        <span className='badge'>{r.control_acronym}</span>
                      </td>
                      <td>
                        <div className='bold' title={titleFull}>
                          {titleShort}
                        </div>
                        <div className='muted small' title={subFull}>
                          {subShort}
                        </div>
                      </td>
                      <td>
                        <StatusPill
                          value={r.compliance_status}
                          kind='compliance'
                        />
                      </td>
                      <td>
                        <StatusPill
                          value={r.implementation_status}
                          kind='impl'
                        />
                      </td>
                      <td>{r.estimated_completion_date || '—'}</td>
                      <td className='right'>
                        <div className='row right gap'>
                          <button
                            className='icon'
                            title='Details'
                            onClick={() => openDetails(r)}
                          >
                            ⋯
                          </button>
                          <button
                            className='icon'
                            title='Edit'
                            onClick={() => openEdit(r)}
                          >
                            ✎
                          </button>
                          <button
                            className='icon danger'
                            title='Delete'
                            onClick={() => doDelete(r.control_acronym)}
                          >
                            🗑
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        <div className='row between mt'>
          <div className='muted small'>
            Page {page} of {totalPages}
          </div>
          <div className='row gap'>
            <button
              className='btn btn-outline'
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
            >
              Prev
            </button>
            <button
              className='btn btn-outline'
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>
      </section>

      {showForm && (
        <ControlForm
          open={showForm}
          onOpenChange={setShowForm}
          initial={editing}
          onSaved={() => {
            setShowForm(false);
            setRefreshTick((t) => t + 1);
          }}
        />
      )}

      {showDetails && detailRow && (
        <DetailDialog
          open={showDetails}
          onOpenChange={setShowDetails}
          row={detailRow}
        />
      )}

      {/* Inline CSS for convenience (you can move this to App.css) */}
      <style>{css}</style>
    </div>
  );
}

function ControlForm({ open, onOpenChange, initial, onSaved }) {
  const isEdit = !!initial;
  const [form, setForm] = useState(() => ({
    control_acronym: initial?.control_acronym || '',
    control_title: initial?.control_title || '',
    compliance_status: initial?.compliance_status || '',
    implementation_status: initial?.implementation_status || '',
    estimated_completion_date: initial?.estimated_completion_date || '',
    recommendations: initial?.recommendations || '',
    implementation_narrative: initial?.implementation_narrative || '',
    control_information: initial?.control_information || '',
    extra: safeStringify(initial?.extra),
  }));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  function onChange(k, v) {
    setForm((prev) => ({ ...prev, [k]: v }));
  }

  async function save() {
    setSaving(true);
    setError('');
    try {
      const payload = {
        control_title: form.control_title || null,
        compliance_status: form.compliance_status || null,
        implementation_status: form.implementation_status || null,
        estimated_completion_date: form.estimated_completion_date || null,
        recommendations: form.recommendations || null,
        implementation_narrative: form.implementation_narrative || null,
        control_information: form.control_information || null,
        extra: safeParseJson(form.extra),
      };
      let res;
      if (isEdit) {
        res = await fetch(
          `${API_BASE}/controls/${encodeURIComponent(form.control_acronym)}`,
          {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          }
        );
      } else {
        res = await fetch(`${API_BASE}/controls`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            control_acronym: form.control_acronym,
            ...payload,
          }),
        });
      }
      if (!res.ok) throw new Error(await res.text());
      onSaved?.();
    } catch (e) {
      setError(e.message || 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  return (
    <dialog open={open} className='modal' onClose={() => onOpenChange(false)}>
      <div className='modal-card'>
        <div className='modal-head'>
          <div className='modal-title'>
            {isEdit ? 'Edit Control' : 'Create Control'}
          </div>
          <button className='icon' onClick={() => onOpenChange(false)}>
            ✕
          </button>
        </div>
        {error && <div className='alert alert-red mb'>{error}</div>}
        <div className='grid'>
          <div>
            <label>Control Acronym</label>
            <input
              value={form.control_acronym}
              disabled={isEdit}
              onChange={(e) => onChange('control_acronym', e.target.value)}
              placeholder='e.g., AU-12'
            />
          </div>
          <div>
            <label>Title</label>
            <input
              value={form.control_title}
              onChange={(e) => onChange('control_title', e.target.value)}
              placeholder='Audit Record Generation'
            />
          </div>
          <div>
            <label>Compliance Status</label>
            <input
              value={form.compliance_status}
              onChange={(e) => onChange('compliance_status', e.target.value)}
              placeholder='compliant / non-compliant / partial'
            />
          </div>
          <div>
            <label>Implementation Status</label>
            <input
              value={form.implementation_status}
              onChange={(e) =>
                onChange('implementation_status', e.target.value)
              }
              placeholder='planned / in-progress / implemented'
            />
          </div>
          <div>
            <label>Estimated Completion Date</label>
            <input
              type='date'
              value={form.estimated_completion_date || ''}
              onChange={(e) =>
                onChange('estimated_completion_date', e.target.value)
              }
            />
          </div>
          <div>
            <label>Recommendations</label>
            <textarea
              rows={3}
              value={form.recommendations}
              onChange={(e) => onChange('recommendations', e.target.value)}
              placeholder='Suggested remediations, scripts, references…'
            />
          </div>
          <div>
            <label>Implementation Narrative</label>
            <textarea
              rows={3}
              value={form.implementation_narrative}
              onChange={(e) =>
                onChange('implementation_narrative', e.target.value)
              }
              placeholder='How this control is or will be implemented…'
            />
          </div>
          <div>
            <label>Control Information</label>
            <textarea
              rows={3}
              value={form.control_information}
              onChange={(e) => onChange('control_information', e.target.value)}
              placeholder='Additional details, mapping to STIG rules, etc.'
            />
          </div>
          <div className='col-span-2'>
            <label>Extra (JSON)</label>
            <textarea
              className='mono'
              rows={8}
              value={form.extra}
              onChange={(e) => onChange('extra', e.target.value)}
              placeholder={`{
  "owner": "SOC",
  "notes": "…"
}`}
            />
          </div>
        </div>
        <div className='modal-foot'>
          <button className='btn btn-ghost' onClick={() => onOpenChange(false)}>
            Cancel
          </button>
          <button className='btn' onClick={save} disabled={saving}>
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </dialog>
  );
}

function FieldRow({ label, value }) {
  return (
    <div className='row fieldrow'>
      <div className='muted small w-32'>{label}</div>
      <div className='grow'>{value ?? '—'}</div>
    </div>
  );
}

function DetailDialog({ open, onOpenChange, row }) {
  const [full, setFull] = useState(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await fetch(
          `${API_BASE}/controls/${encodeURIComponent(row.control_acronym)}`
        );
        if (!res.ok) throw new Error(await res.text());
        const json = await res.json();
        if (alive) setFull(json);
      } catch (e) {
        if (alive) setErr(e.message || 'Failed to load details');
      }
    })();
    return () => {
      alive = false;
    };
  }, [row.control_acronym]);

  const d = full || row;

  return (
    <dialog open={open} className='modal' onClose={() => onOpenChange(false)}>
      <div className='modal-card'>
        <div className='modal-head'>
          <div className='row gap wrap'>
            <span className='badge'>{d.control_acronym}</span>
            <div
              className='bold ellipsis'
              title={d.control_title || '(untitled)'}
            >
              {shrinkText(d.control_title || '(untitled)', TITLE_MAX)}
            </div>
          </div>
          <button className='icon' onClick={() => onOpenChange(false)}>
            ✕
          </button>
        </div>
        {err && <div className='alert alert-red mb'>{err}</div>}
        <div className='stack'>
          <FieldRow
            label='Compliance'
            value={<StatusPill value={d.compliance_status} kind='compliance' />}
          />
          <FieldRow
            label='Implementation'
            value={<StatusPill value={d.implementation_status} kind='impl' />}
          />
          <FieldRow
            label='Target Date'
            value={d.estimated_completion_date || '—'}
          />
          <FieldRow
            label='Recommendations'
            value={<pre className='pre'>{d.recommendations || '—'}</pre>}
          />
          <FieldRow
            label='Implementation Narrative'
            value={
              <pre className='pre'>{d.implementation_narrative || '—'}</pre>
            }
          />
          <FieldRow
            label='Control Information'
            value={<pre className='pre'>{d.control_information || '—'}</pre>}
          />
          <div>
            <div className='muted small mb-1'>Extra (JSON)</div>
            <pre className='pre mono'>{safeStringify(d.extra)}</pre>
          </div>
        </div>
      </div>
    </dialog>
  );
}

// Minimal CSS — move to App.css if you prefer
const css = `
:root{ --b:#111827; --t:#374151; --muted:#6b7280; --bg:#f8fafc; --card:#ffffff; --bd:#e5e7eb; --accent:#2563eb; }
*{ box-sizing:border-box }
body{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, Noto Sans, "Apple Color Emoji","Segoe UI Emoji"; background:var(--bg); color:var(--b); }
.page{margin:0 auto; padding:24px; }
.topbar{ display:flex; align-items:center; justify-content:space-between; margin-bottom:16px; }
.topbar h1{ margin:0 0 6px 0; font-size:22px }
.sub{ color:var(--muted); font-size:12px }
.card{ background:var(--card); border:1px solid var(--bd); border-radius:16px; padding:16px; margin-bottom:16px; box-shadow:0 1px 2px rgba(0,0,0,0.04) }
.card-title{ font-size:14px; color:var(--t); margin:0 0 12px 0; font-weight:600 }
.filters{ display:grid; grid-template-columns: 1fr 180px 200px 140px 120px; gap:12px; align-items:end }
.field label{ display:block; font-size:12px; color:var(--muted); margin-bottom:6px }
.field input, .field select, input, select, textarea{ width:100%; border:1px solid var(--bd); padding:9px 10px; border-radius:10px; outline:none; font-size:14px; }
.field textarea, textarea{ width:100%; border:1px solid var(--bd); padding:10px; border-radius:10px; outline:none; font-size:14px; }
.row{ display:flex; align-items:center }
.row.gap{ gap:8px }
.row.between{ justify-content:space-between }
.row.right{ justify-content:flex-end }
.stack{ display:flex; flex-direction:column; gap:10px }
.mt{ margin-top:12px }
.mb{ margin-bottom:12px }
.grow{ flex:1 }
.center{ text-align:center }
.right{ text-align:right }
.p-24{ padding:24px }
.bold{ font-weight:600 }
.small{ font-size:12px }
.muted{ color:var(--muted) }
.ellipsis{ white-space:nowrap; overflow:hidden; text-overflow:ellipsis }
.badge{ display:inline-block; padding:4px 8px; border-radius:999px; background:#f3f4f6; border:1px solid var(--bd); font-size:12px }
.btn{ background:var(--b); color:white; border:none; border-radius:10px; padding:9px 14px; cursor:pointer }
.btn:hover{ filter:brightness(0.95) }
.btn:disabled{ opacity:0.6; cursor:not-allowed }
.btn-outline{ background:white; color:var(--b); border:1px solid var(--bd) }
.btn-secondary{ background:var(--accent) }
.btn-ghost{ background:transparent; color:var(--b); border:1px dashed var(--bd) }
.icon{ background:transparent; border:1px solid var(--bd); border-radius:10px; padding:6px 8px; cursor:pointer }
.icon:hover{ background:#f9fafb }
.icon.danger{ color:#b91c1c; border-color:#fecaca }
.alert{ padding:10px 12px; border-radius:10px; border:1px solid var(--bd); font-size:14px }
.alert-red{ background:#fef2f2; border-color:#fecaca; color:#991b1b }
.table-wrap{ overflow:auto; border:1px solid var(--bd); border-radius:12px }
.table{ width:100%; border-collapse:separate; border-spacing:0 }
.table thead th{ position:sticky; top:0; background:#f9fafb; text-align:left; padding:10px 12px; font-size:12px; color:var(--muted); border-bottom:1px solid var(--bd) }
.table tbody td{ padding:12px; border-bottom:1px solid var(--bd); vertical-align:top }
.table .hover:hover{ background:#fafafa }
.w-20{ width:120px } .w-28{ width:140px } .w-32{ width:180px } .w-36{ width:200px } .w-32px{ width:32px }
.pill{ display:inline-block; padding:4px 8px; border-radius:999px; font-size:12px; border:1px solid var(--bd); background:#f3f4f6 }
.pill-green{ background:#ecfdf5; color:#065f46; border-color:#a7f3d0 }
.pill-emerald{ background:#ecfdf5; color:#065f46; border-color:#a7f3d0 }
.pill-red{ background:#fef2f2; color:#991b1b; border-color:#fecaca }
.pill-amber{ background:#fffbeb; color:#92400e; border-color:#fde68a }
.pill-gray{ background:#f3f4f6; color:#374151; border-color:#e5e7eb }
.pill-indigo{ background:#eef2ff; color:#3730a3; border-color:#c7d2fe }
.modal{ border:none; padding:0; }
.modal::backdrop{ background:rgba(0,0,0,0.18) }
.modal-card{ width:min(720px, 92vw); background:white; border:1px solid var(--bd); border-radius:16px; overflow:hidden; display:flex; flex-direction:column }
.modal-head{ display:flex; align-items:center; justify-content:space-between; padding:12px 14px; border-bottom:1px solid var(--bd) }
.modal-title{ font-weight:600 }
.modal-foot{ display:flex; gap:8px; justify-content:flex-end; padding:12px 14px; border-top:1px solid var(--bd) }
.grid{ display:grid; grid-template-columns:1fr 1fr; gap:12px; padding:14px }
.grid .col-span-2{ grid-column:1 / span 2 }
.pre{ background:#f9fafb; border:1px solid var(--bd); border-radius:10px; padding:10px; white-space:pre-wrap; font-size:13px }
.mono{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace }
.fieldrow{ padding:8px 0; border-bottom:1px solid #f3f4f6 }
.wrap{ flex-wrap:wrap }
`;

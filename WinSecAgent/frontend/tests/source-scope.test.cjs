// Exercise the actual store with TypeScript transpilation; no browser or API server needed.
const fs = require('node:fs');
const ts = require('typescript');
const { test } = require('node:test');
const assert = require('node:assert/strict');
require.extensions['.ts'] = (module, filename) => {
  const { outputText } = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  });
  module._compile(outputText, filename);
};
const { useAppStore: store } = require('../src/stores/appStore.ts');
const { api } = require('../src/services/api.ts');
const { sourceScopeFor } = require('../src/services/logSource.ts');
const initial = store.getState();

test('pasted demo metadata and legacy demo sources stay out of actual records', () => {
  assert.equal(sourceScopeFor({ is_demo: true, source_type: 'windows_manual' }), 'demo');
  assert.equal(sourceScopeFor({ source_type: 'windows_demo' }), 'demo');
  assert.equal(sourceScopeFor({ is_demo: false, source_type: 'windows_log' }), 'actual');
});

test('switching source clears the selected demo report and pending selection cannot restore it', async () => {
  store.setState(initial, true);
  store.setState({ sourceScope: 'demo', selectedIncidentId: 1, selectedIncident: { id: 1 },
    report: { id: 3 }, evidence: [{ id: 2 }], actions: [{ id: 4 }], agentRuns: [{ id: 5 }] });
  let resolve;
  api.incidents.get = () => new Promise(done => { resolve = done; });
  const pending = store.getState().selectIncident(2);
  store.getState().setSourceScope('actual');
  resolve({ id: 2, queue: 'alerts', alert: { is_demo: true, source_type: 'windows_demo' } });
  await pending;
  const state = store.getState();
  assert.equal(state.sourceScope, 'actual');
  assert.equal(state.selectedIncidentId, null);
  assert.equal(state.selectedIncident, null);
  assert.equal(state.report, null);
  assert.deepEqual([state.evidence, state.actions, state.agentRuns], [[], [], []]);
});

test('loading a demo and then importing an actual log each select the matching source view', async () => {
  store.setState(initial, true);
  api.incidents.get = async id => ({ id, queue: 'logs',
    alert: { is_demo: id === 1, source_type: id === 1 ? 'windows_demo' : 'windows_log' } });
  await store.getState().selectIncident(1);
  assert.equal(store.getState().sourceScope, 'demo');
  await store.getState().selectIncident(2);
  assert.equal(store.getState().sourceScope, 'actual');
  assert.equal(store.getState().selectedIncidentId, 2);
});

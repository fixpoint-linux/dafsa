// shell/shell.js — @mfe/framework thin-shell entry.
//
// Boots a single-route app ('/' -> template 'dafsa') and mounts the Elm
// docs MFE into the [data-mfe="dafsa-page"] slot of that template.
//
// The page ships statically pre-rendered (see scripts/ssg.mjs): the #app root
// carries an `ssr` attribute, so createApp rehydrates the existing DOM in
// place instead of wiping it and re-fetching the template on first paint.

import { createApp } from '@mfe/framework';

// The dafsa site is served at /dafsa/ on fixpointlinux.org. Its route table
// mirrors the main site exactly: '/' is the fixpoint-linux landing and
// '/dafsa' is this dafsa page. Matching the main site means a data-mfe-route
// like '/dafsa' or '/' resolves the same way on either page, so cross-site
// MFE nav links agree on the target route.
const app = await createApp({
  root: document.getElementById('app'),
  routes: [
    { path: '/', template: 'fixpoint', name: 'home' },
    { path: '/dafsa', template: 'dafsa', name: 'dafsa' },
  ],
  basePath: '/',
  // dafsa's templates are served from /dafsa/shell/templates (the main site
  // owns /shell/templates). Pin the baseURL here so both route templates
  // resolve under this site's shell regardless of the deep-link subpath.
  baseURL: '/dafsa/shell/templates',
  // The SSG output only pre-renders the dafsa home route. Rehydrate only when
  // the current pathname matches that pre-rendered route (i.e. the dafsa page);
  // any other path (including the landing) needs a fresh client render.
  ssr: (window.location.pathname.replace(/\/+$/, '') || '/') === '/dafsa',
});

// Expose the app handle so the shell/host can inspect or drive it later.
window.__dafsaApp = app;

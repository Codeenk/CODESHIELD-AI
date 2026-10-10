---
name: cwe-79-xss
description: Detect and repair cross-site scripting in DOM sinks and reflected responses
cwe: CWE-79
owasp: A03:2021
targets: [detection, explanation, repair]
triggers: [innerHTML, outerHTML, document.write, dangerouslySetInnerHTML, getParameter, response]
---

# CWE-79 — Cross-site Scripting

## What it is
Attacker-controlled markup executes as script in a victim's browser.

## How to spot it
- DOM sinks: `.innerHTML`, `.outerHTML`, `document.write`, `dangerouslySetInnerHTML`,
  `insertAdjacentHTML`.
- Reflected responses: Java `response.getWriter().print(request.getParameter(...))`, or
  template output that is not auto-escaped (e.g. `| safe`, `{!! !!}`).

## How to fix
- Prefer `textContent` over `innerHTML`.
- Sanitise with a vetted library (DOMPurify) when HTML is genuinely required.
- Encode on output with a context-aware encoder; set a Content-Security-Policy as defence in
  depth.

## Explanation to give the developer
Point at the sink and the source, then show the `textContent`/`DOMPurify` rewrite.

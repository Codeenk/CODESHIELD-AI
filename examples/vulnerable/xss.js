// Example: DOM XSS (CWE-79). Intentionally vulnerable — do not deploy.

function renderProfile(user) {
  const container = document.getElementById("profile");
  // Vulnerable: user-controlled data becomes HTML.
  container.innerHTML = "<h1>" + user.name + "</h1>";
}

function runCustom(expr) {
  // Vulnerable: dynamic code evaluation.
  return eval(expr);
}

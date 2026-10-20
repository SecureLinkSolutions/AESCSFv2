// Show errors from htmx requests (htmx doesn't swap 4xx/5xx responses by default).
document.addEventListener("htmx:responseError", (event) => {
  const text = event.detail.xhr.responseText || "Request failed";
  window.alert(text.length > 300 ? "Request failed" : text);
});

// Plain (non-htmx) forms that need a confirmation step. Inline handlers are blocked by the CSP.
document.addEventListener("submit", (event) => {
  const message = event.target.dataset && event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

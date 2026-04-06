/* AESCSF v2 Evidence Tracker — runtime configuration
 *
 * This file is served by Nginx and is auto-generated from environment
 * variables at container start (see nginx/entrypoint.sh).
 *
 * For LOCAL development without Docker, edit the values below directly.
 * Leave clientId and tenantId empty to disable SSO and run without auth.
 */
window.__AESCSF_CONFIG__ = {
  storageMode:       "local",   /* "api" for backend persistence, "local" for localStorage */
  apiBaseUrl:        "/api",
  apiAssessmentPath: "/assessment",
  clientId:          "",        /* Azure AD Application (client) ID */
  tenantId:          ""         /* Azure AD Directory (tenant) ID   */
};

# Onboarding a client for scanning

1. **Get the signed authorisation letter.** It must name:
   - the targets (domains, IPs, CIDRs)
   - the scanner source IP (the Linode's public IP)
   - the start and end of the testing window
   - a contact at the client, and who signed
2. **Create the client** at `/app/clients`.
3. **Upload the letter** on the client page, entering the same window and source
   IP as the letter states. Only PDFs are accepted.
4. **Add scope items** exactly as listed in the letter.
   - A domain covers all its subdomains. If the letter only authorises
     `shop.example.com`, add `shop.example.com`, not `example.com`.
   - CIDRs larger than /24 are refused. Split them, or raise
     `MIN_CIDR_PREFIX_V4` only if the letter genuinely covers more.
5. **Verify each item.**
   - Domains: open *How to verify*, send the TXT record (or the well-known file
     contents) to the client, and press *Verify* once they confirm it's live.
     The row updates by itself when the check finishes.
   - IPs and CIDRs: check the address really is in the letter, tick the box and
     press *Confirm*. This is recorded against your name.
6. Only items marked **verified** under a **live** authorisation will be
   scanned (from M3).

## When things change

- **Letter withdrawn or superseded:** revoke the authorisation. Its scope stops
  being scannable immediately.
- **Target leaves scope:** remove the item. The removal is kept in the audit log.
- **Verification failed:** the reason is shown on the row. Common causes: the
  TXT record hasn't propagated yet, the record was added at the apex instead of
  `_securelink-verify.<domain>`, or the file sits behind a redirect.

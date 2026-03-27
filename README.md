# AESCSF v2 Evidence Tracker
Overview

The AESCSF v2 Evidence Tracker is a single-file HTML assessment and evidence management tool designed to support organisations implementing and assessing against the Australian Energy Sector Cyber Security Framework (AESCSF) Version 2. The tool allows assessors to record evidence, track implementation status, manage remediation timelines, compare yearly assessments, and generate reports within a portable offline application that does not require a server or database.

Application

The tracker is designed to function as a lightweight audit and cyber security maturity assessment tool. It enables users to document evidence for each AESCSF practice, assign ownership, record remediation actions, set target dates, and monitor progress over time. The application includes a dashboard summary, radar charts for domain maturity visualisation, a remediation timeline, gap register export, PDF reporting, evidence reference links, AEMO CSV export, and a comparison view for analysing previous and current year assessments.

Standard practices are assessed based on maturity indicator levels (MIL). MIL-1 practices use Yes / No status options, MIL-2 and MIL-3 practices use Not, Partially, Largely, and Fully status options, and Anti-Practices use Met or Not Met. All assessment data is stored locally in the browser and can be exported and imported using JSON files for backup or transfer between systems.

Usage

To use the tool, download the HTML file and open it in a web browser such as Chrome or Edge. Enter assessment information for each practice and save the assessment within the browser. Export the JSON file regularly to maintain backups. The dashboard provides a summary of the assessment posture, the timeline assists with remediation scheduling, the comparison page allows year-on-year assessment comparison, and the reporting function can generate a PDF summary for audit or management reporting purposes. The AEMO export function allows export of practice status into the required CSV template format.

Purpose

This tool is intended for AESCSF self-assessments, cyber security maturity assessments, evidence tracking, remediation planning, internal audits, and preparation for external audits or regulatory reviews.

Technical Information

The application is a standalone HTML file that runs entirely in the browser using local storage for data persistence. No installation, database, or server infrastructure is required for standalone use. The application has been structured to allow future migration to on-prem or cloud hosting with a backend database and API without major redesign. Reports, gap registers, JSON backups, and AEMO CSV exports can be generated for external use.

Disclaimer

This tool is provided for assessment and evidence tracking purposes only and does not guarantee compliance with AESCSF or any regulatory requirement. Users are responsible for validating assessments, evidence, and compliance outcomes.

AI was used in creating this tool.

![AESCSF Dashboard](https://github.com/SecureLinkSolutions/AESCSFv2/blob/main/Dashboard.png)

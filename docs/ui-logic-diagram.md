# AESCSF v2 — UI Logic Diagram

## Authentication & Initialisation Flow

```mermaid
flowchart TD
    Browser["Browser loads /"] --> Nginx["nginx\n(auth_request gate)"]
    Nginx -->|"No session cookie"| OAuth2["oauth2-proxy\n/oauth2/sign_in"]
    OAuth2 --> EntraID["Microsoft Entra ID\nSSO login"]
    EntraID -->|"Auth code"| Callback["oauth2-proxy\n/oauth2/callback\nSets _aescsf_session cookie"]
    Callback --> SPA["SPA loads\nindex.html"]

    Nginx -->|"Valid session cookie"| SPA

    SPA --> InitAPI["initializeFromApi()"]
    InitAPI --> GetMe["GET /api/me\n→ { oid, role, domains, objectives }"]
    GetMe --> RBAC["window.__AESCSF_RBAC__\n= { role, domains, objectives, _oid }"]
    RBAC --> ApplyUI["applyRbacUI(me)\nShow/hide tabs & features"]
    ApplyUI --> LoadData["Load assessment + confidence\nin parallel"]
    LoadData --> Render["render() + renderDashboard()"]
```

---

## User Roles & Page Access

```mermaid
flowchart LR
    subgraph Roles["Two Roles"]
        Admin["Admin"]
        User["Contributor / User"]
    end

    subgraph Pages["Navigation Tabs"]
        Assessment["Assessment\n(practices form)"]
        Timeline["Target Date Timeline"]
        Dashboard["Dashboard\n(charts & stats)"]
        Comparison["Comparison\n(snapshots)"]
        AuditLog["Audit Log"]
        AdminPanel["Admin Panel"]
    end

    Admin -->|"visible"| Assessment
    Admin -->|"visible"| Timeline
    Admin -->|"visible"| Dashboard
    Admin -->|"visible"| Comparison
    Admin -->|"visible"| AuditLog
    Admin -->|"visible"| AdminPanel

    User -->|"visible"| Assessment
    User -->|"visible"| Timeline
    User -->|"hidden — tab not shown"| Dashboard
    User -->|"hidden — tab not shown"| Comparison
    User -->|"hidden — tab not shown"| AuditLog
    User -->|"hidden — tab not shown"| AdminPanel
```

---

## Assessment Page — Practice Filtering by Role

```mermaid
flowchart TD
    Load["Assessment page loads\nrender()"] --> Filter["getFilteredPractices()\napplies RBAC filter"]

    Filter --> IsAdmin{{"role === admin?"}}

    IsAdmin -->|"Yes"| AllPractices["All 354 practices\nacross all 11 domains"]
    IsAdmin -->|"No"| HasAssignment{{"Has domain or\nobjective assignments?"}}

    HasAssignment -->|"Neither"| AllPractices2["All 354 practices\n(unassigned = no restriction)"]
    HasAssignment -->|"Has domain assignment"| DomainPractices["Practices within\nassigned domains only"]
    HasAssignment -->|"Has objective assignment"| ObjPractices["Practices within\nassigned objective groups\n(e.g. ACCESS-1 → ACCESS-1a/b/c)"]
    HasAssignment -->|"Both"| BothPractices["Union of domain\nand objective practices"]

    AllPractices --> AssessmentView["Assessment view\nwith all features"]
    AllPractices2 --> AssessmentView2["Assessment view\nwith all features"]
    DomainPractices --> AssessmentView3["Assessment view\n(filtered subset)"]
    ObjPractices --> AssessmentView4["Assessment view\n(filtered subset)"]
    BothPractices --> AssessmentView5["Assessment view\n(filtered subset)"]
```

---

## Assessment Page — Features by Role

```mermaid
flowchart LR
    subgraph PracticeCard["Per-Practice Card"]
        Status["Status dropdown\n(Not Assessed / In Progress / etc.)"]
        Evidence["Evidence text"]
        Gap["Gap text"]
        Notes["Notes"]
        Owner["Owner"]
        TargetDate["Target date"]
        Files["File attachments"]
        Confidence["★ Confidence rating\n1–5 stars + notes"]
    end

    Admin2["Admin"] -->|"sees & edits"| Status
    Admin2 -->|"sees & edits"| Evidence
    Admin2 -->|"sees & edits"| Gap
    Admin2 -->|"sees & edits"| Notes
    Admin2 -->|"sees & edits"| Owner
    Admin2 -->|"sees & edits"| TargetDate
    Admin2 -->|"sees & edits"| Files
    Admin2 -->|"sees & edits"| Confidence

    User2["Contributor"] -->|"sees & edits"| Status
    User2 -->|"sees & edits"| Evidence
    User2 -->|"sees & edits"| Gap
    User2 -->|"sees & edits"| Notes
    User2 -->|"sees & edits"| Owner
    User2 -->|"sees & edits"| TargetDate
    User2 -->|"sees & edits"| Files
    User2 -->|"hidden"| Confidence
```

---

## Assessment Save — Server-Side Enforcement

```mermaid
flowchart TD
    Save["PUT /api/assessment"] --> AuthCheck["requireAuth\nrequireAdmin skipped — any logged-in user"]
    AuthCheck --> IsAdminSave{{"role === admin?"}}

    IsAdminSave -->|"Yes"| SaveAll["Save all 354 practices\n(no filtering)"]

    IsAdminSave -->|"No"| HasAssign{{"Has domain or\nobjective assignments?"}}
    HasAssign -->|"Neither"| SaveAll2["Save all practices\n(no restriction)"]
    HasAssign -->|"Yes"| FilterSave["Filter to only\nassigned practices\nbefore writing to DB"]
    FilterSave --> SaveFiltered["Save allowed\npractices only"]
```

---

## Admin Panel — Features

```mermaid
flowchart TD
    AdminTab["Admin tab\n(admin only)"] --> UserMgmt["User & Access Management"]
    AdminTab --> Responses["Multi-Respondent Responses\n(side-by-side per practice)"]

    UserMgmt --> RoleMgmt["Set role:\nAdmin / User"]
    UserMgmt --> DomainAssign["Domain Assignments\n11 domains — tick boxes"]
    UserMgmt --> ObjAssign["Objective Assignments\nFiner than domain\n(e.g. ACCESS-1, GOVERN-2)"]
    UserMgmt --> MergedView["Load Merged View\nCombined answer from all contributors"]

    Responses --> RespFilters["Filter by domain\nor objective group"]
    Responses --> RespTable["Table per practice:\nRespondent | Status | Evidence | Gap | Notes | Owner"]

    DomainAssign -->|"User assigned to\ne.g. ACCESS domain"| UserSeesAccess["That user sees only\nACCESS practices\nin Assessment view"]
    ObjAssign -->|"User assigned to\ne.g. ACCESS-1"| UserSeesObj["That user sees only\nACCESS-1a/b/c practices\nin Assessment view"]
```

---

## Multi-Respondent Flow

```mermaid
sequenceDiagram
    participant Admin
    participant InfraUser as Infra User
    participant SDUser as Service Desk User
    participant API

    Admin->>API: PUT /admin/users/infra-oid/objective-assignments { objectives: ["ACCESS-1"] }
    Admin->>API: PUT /admin/users/sd-oid/objective-assignments { objectives: ["ACCESS-1"] }

    InfraUser->>API: GET /api/me → { objectives: ["ACCESS-1"] }
    InfraUser->>API: PUT /api/assessment { ACCESS-1a: { status:"Implemented", evidence:"..." } }
    Note over InfraUser,API: Saved under infra-oid only

    SDUser->>API: GET /api/me → { objectives: ["ACCESS-1"] }
    SDUser->>API: PUT /api/assessment { ACCESS-1a: { status:"Partially Implemented", evidence:"..." } }
    Note over SDUser,API: Saved under sd-oid only

    Admin->>API: GET /api/admin/responses
    API-->>Admin: { "ACCESS-1a": [ {infra answer}, {sd answer} ] }
    Note over Admin: Side-by-side view — no merging, no winner
```

---

## Incomplete Assignment Banner

```mermaid
flowchart TD
    Init["initializeFromApi() completes"] --> HasObj{{"User has objective\nassignments?"}}
    HasObj -->|"No"| NoAction["No banner"]
    HasObj -->|"Yes"| CheckComplete["checkAssignmentCompletion(objectives)\nCount practices with status\n= 'Not Assessed' or missing"]
    CheckComplete --> AllDone{{"All complete?"}}
    AllDone -->|"Yes"| NoAction
    AllDone -->|"No"| ShowBanner["Show amber banner:\n'You have N assigned practices\nnot yet assessed.'"]
    ShowBanner --> Dismiss["User clicks Dismiss\n→ banner hidden"]
```

---

## Dashboard — Admin-Only Features

```mermaid
flowchart LR
    Dashboard["Dashboard\n(admin only)"] --> Overview["Summary stats\n(total, implemented, gaps, overdue)"]
    Dashboard --> RadarChart["Domain maturity radar\n(overall)"]
    Dashboard --> SPBreakdown["SP-1 / SP-2 / SP-3\nbreakdown radar + table\n(admin only section)"]
    Dashboard --> GapList["Open gaps list"]
    Dashboard --> OverdueList["Overdue practices"]
```

---

## Storage Modes

```mermaid
flowchart TD
    Mode{{"AESCSF_STORAGE_MODE"}}
    Mode -->|"api"| ApiMode["API mode\n(default — recommended)"]
    Mode -->|"local"| LocalMode["Local mode\n(browser localStorage only)"]

    ApiMode --> AllFeatures["All features enabled:\n• Server-side RBAC\n• Multi-user\n• Objective assignments\n• Audit log\n• Snapshots\n• File uploads\n• Confidence ratings"]

    LocalMode --> LimitedFeatures["Limited:\n• No login / no RBAC\n• Single-user only\n• No audit log\n• No snapshots\n• No file uploads\n• No confidence ratings"]
```

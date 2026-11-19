# CONNECTIFYU - College Event Management System India

A comprehensive, production-hardened Django web platform engineered for Indian engineering colleges and universities to automate event proposal approvals, manage multi-stage institutional scrutiny, dispatch campus logistics, and enforce anti-proxy student attendance.

---

## 🛡️ Security Audit & Hardening (Fix Commit `ed886b6`)

The application has undergone an exhaustive security audit covering **25 vulnerability fixes** (6 Critical, 9 High, 10 Medium/Low) verified with comprehensive automated test suites (`events.tests` and `events.tests_bugs`):

| # | Vulnerability Fixed | Severity | Impact & Fix Implemented |
|:---|:---|:---|:---|
| **1** | **Unauthenticated Account Takeover** (`switch_user_view`) | **CRITICAL** | Protected with `@login_required`, `@user_passes_test(is_superuser)`, and `DEBUG` check. Restricted `demo_roles_processor` to authenticated superusers. |
| **2** | **`simulateSelfie()` Anti-Proxy Backdoor** | **CRITICAL** | Removed `simulateSelfie()` and "Generate Demo Selfie" bypass from `checkin_selfie.html`. Real front-camera physical presence now strictly required. |
| **3** | **Static QR Token Never Expiring** | **CRITICAL** | Eliminated static token fallback in `validate_rotating_token()`. Handled UUID splitting with `rsplit('_', 2)`. Time window strictly enforced. |
| **4** | **IDOR on Proposals, Reports & Details** | **CRITICAL** | Sequential ID enumeration defeated by raising `Http404` for unauthorized viewers in `proposal_detail_view`, `compliance_report_view`, and `event_public_detail_view`. |
| **5** | **Selfie Media Filename Enumeration** | **CRITICAL** | Unpredictable UUID-based storage paths ensure privacy and prevent biometric harvesting. |
| **6** | **Feedback Gate Bypass (Free Verified Status)**| **CRITICAL** | Enforced that student must be physically checked in (`status == 'CHECKED_IN'`) before feedback can be submitted. |
| **7** | **HOD Cross-Department Privilege Escalation** | **HIGH** | Tightened `is_awaiting_user()` so only the genuine `head == user` of the organizing department can approve the HOD stage. |
| **8** | **`REVISE_BUDGET` Inverted Logic & Precision** | **HIGH** | Inverted check corrected (`or`), profile guard added, and float replaced with `Decimal` bounded to `₹9,999,999,999.99`. |
| **9** | **Poster XSS & File Size Bypass** | **HIGH** | Whitelist regex validation for `poster_preset`, 5MB file size limit, and PIL image header verification in `publish_event_view`. |
| **10**| **Logistics Notification Duplication** | **HIGH** | Added database constraint `unique_together = ('proposal', 'logistics_type')` and `get_or_create` idempotency. |
| **11**| **Email Dispatch Inside DB Transaction** | **HIGH** | Deferred email dispatch using `transaction.on_commit` to prevent rollbacks and phantom emails. |
| **12**| **CSRF Logout Attack (Logout via GET)** | **HIGH** | Changed `logout_view` to `@require_POST` and updated navbar to POST form with CSRF token. |
| **13**| **Registration & Check-In Race Conditions** | **HIGH** | Wrapped operations in `@transaction.atomic` with row-level `select_for_update()`. |
| **14**| **Proposal Creation/Edit Input Validation** | **HIGH** | Mandatory non-empty title, bounded `Decimal` budget, positive attendee counts, and chronological date validation. |
| **15**| **Registration on Draft, Full, or Past Events** | **HIGH** | Enforced event capacity checks, `status == 'APPROVED'`, and non-expired event date constraints. |
| **16**| **Login Page Credential Leaks** | **MEDIUM** | Wrapped demo switcher and persona links to render strictly for active superusers in DEBUG sessions. |
| **18**| **Custom Approval Chain Role Injection** | **MEDIUM** | Whitelist validation against known institutional roles in `get_default_chain`. |
| **19**| **Missing Approval Chain on Edit** | **MEDIUM** | Auto-rebuilds default approval chain if missing during proposal edits. |
| **20**| **Silent Approval Action Fallthrough** | **MEDIUM** | Fails closed with an explicit error message on unrecognized actions. |
| **23**| **Loose Staff Department Lookup** | **MEDIUM** | Uses `name__iexact` first, falling back to `name__icontains` only as a logged warning. |
| **25**| **Duplicate Hidden Token Form Inputs** | **LOW** | Cleaned up conflicting `name="token"` inputs in the check-in template. |

---

## 🚀 Core Features

### 1. Pre-Provisioned Institutional Database
- **No Self-Registration**: Accounts are pre-provisioned in an institutional directory, stopping unauthenticated privilege escalation.
- **Superadmin User Directory** (`/superadmin/users/`): Complete oversight over student roll numbers, faculty departments, and roles.

### 2. Multi-Stage Approval Engine & Department Routing
- **Preset Chains & Custom Builder**:
  - Academic & Research Chain (routes to specific department HOD &rarr; Dean R&D &rarr; Dean Finance &rarr; Dean Academics &rarr; Director).
  - Student Fest Chain (Club Advisor &rarr; Dean Student Welfare &rarr; Dean Finance &rarr; Dean Academics &rarr; Director).
  - Institute Mega Event Chain (Registrar/HR &rarr; Dean Research &rarr; Dean Finance &rarr; Dean Academics &rarr; Director).
  - Custom Chain Builder with statutory mandatory lock for **Dean of Finance**, **Dean of Academics**, and **Director**.

### 3. Faculty Poster Gate & Publishing
- Approval clears logistics automatically (Mess, Transport, AV/Estate) and leaves the event in `APPROVED_PENDING_PUBLISH`.
- The faculty coordinator uploads the official poster and triggers the final campus release.

### 4. Dynamic Rotating QR & Live Selfie Attendance
- Projected on the auditorium screen (`/events/<id>/live/`), the QR code rotates every 20 seconds.
- Student scans QR on their phone and captures a real front-camera selfie.
- Attendance upgrades from `CHECKED_IN` to `VERIFIED` only after completing a 3-category feedback rating.

### 5. Organizer Audit Roster & Post-Event Compliance
- Dedicated roster inside the proposal detail view showing registered students, live check-in selfies, timestamps, and feedback ratings.
- Downloadable compliance report with budget analysis (in $\text{₹}$ INR) and attendance metrics.

---

## 👥 Pre-Provisioned Accounts (Password: `password123`)

| Username | Role | Full Name & Office | Notes |
|:---|:---|:---|:---|
| **`admin`** | **Superadmin** | Central Administrator (IT Centre) | Superuser with directory management & persona switching |
| **`faculty`** | **Faculty** | Prof. Rajesh Sharma (CSE Dept) | Proposes events, uploads poster, publishes to campus |
| **`faculty_ece`** | **Faculty** | Dr. Arvind Swaminathan (ECE Dept) | Coordinator for ECE Department events |
| **`hod_cse`** | **HOD** | Dr. K. V. Ramanathan (HOD CSE) | Stage 1 Approver for CSE events |
| **`hod_ece`** | **HOD** | Dr. Sunita Kulkarni (HOD ECE) | Stage 1 Approver for ECE events |
| **`hod_mech`** | **HOD** | Dr. Vikramaditya Rathore (HOD Mech) | Stage 1 Approver for Mechanical events |
| **`club_lead`** | **Club Head** | Prof. Priya Nair (Robotics Society) | Faculty Advisor for student club events |
| **`registrar`** | **Registrar** | Smt. Sunita Deshmukh (Admin/HR) | Approver for Institute-wide conclaves |
| **`dean_research`**| **Dean** | Dr. P. Venkatraman (Dean R&D) | Speaker vetting & academic review |
| **`dean_dsw`** | **Dean** | Dr. Alok Sen (Dean Student Welfare) | Club & festival safety review |
| **`dean_finance`** | **Dean (Mandatory)** | Dr. Suresh Chandra (Dean Finance) | Budget sanction & revision in ₹ INR |
| **`dean_academics`**| **Dean (Mandatory)** | Dr. Meenakshi Sundaram (Dean Academics) | Academic schedule & duty leaves |
| **`director`** | **Director (Mandatory)**| Dr. R. Chidambaram (Director) | Final executive clearance & logistics hook |
| **`student1`** | **Student** | Aarav Patel (21BCSE101 - CSE) | Pre-enrolled student attendee |
| **`student2`** | **Student** | Ananya Sen (21BECE034 - ECE) | Pre-enrolled verified volunteer |

---

## ⚡ Running & Testing

### Run Server
```powershell
cd C:\Users\abhis\.gemini\antigravity\scratch\college_event_system
python manage.py runserver
```
Visit **`http://127.0.0.1:8000/`**.

### Execute Test Suite
```powershell
python manage.py test events
```
All unit tests and security bug regression suites run cleanly (`OK`).

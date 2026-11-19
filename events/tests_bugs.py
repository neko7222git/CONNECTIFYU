import time
from datetime import timedelta
from decimal import Decimal
from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.files.uploadedfile import SimpleUploadedFile

from events.models import (
    UserProfile, OrganizingUnit, EventProposal,
    ApprovalLog, EventRegistration, EventFeedback, LogisticsNotification
)
from events.utils import get_default_chain, dispatch_logistics_notifications


class SecurityAuditBugFixTestCase(TestCase):
    """
    Test suite verifying the 25 security audit vulnerability fixes (CONNECTIFYU ed886b6).
    Covers IDOR, Account Takeover, CSRF, Replay, Injection, and Input Validation.
    """

    def setUp(self):
        # 1. Setup Personas
        self.admin = User.objects.create_superuser(username='admin', password='password123', email='admin@college.ac.in')
        UserProfile.objects.create(user=self.admin, role='DIRECTOR', department='Directorate')

        self.faculty = User.objects.create_user(username='faculty_user', password='password123')
        UserProfile.objects.create(user=self.faculty, role='FACULTY', department='Computer Science & Engineering')

        self.hod_cse = User.objects.create_user(username='hod_cse_user', password='password123')
        UserProfile.objects.create(user=self.hod_cse, role='HOD', department='Computer Science & Engineering')

        self.hod_ece = User.objects.create_user(username='hod_ece_user', password='password123')
        UserProfile.objects.create(user=self.hod_ece, role='HOD', department='Electronics & Communication Engineering')

        self.dean_fin = User.objects.create_user(username='dean_fin_user', password='password123')
        UserProfile.objects.create(user=self.dean_fin, role='DEAN_ACCOUNTS', department='Finance Office')

        self.student1 = User.objects.create_user(username='student1', password='password123')
        UserProfile.objects.create(user=self.student1, role='STUDENT', department='Computer Science', roll_or_emp_id='21BCSE101')

        self.student2 = User.objects.create_user(username='student2', password='password123')
        UserProfile.objects.create(user=self.student2, role='STUDENT', department='Electronics', roll_or_emp_id='21BECE002')

        # 2. Setup Organizing Units
        self.dept_cse = OrganizingUnit.objects.create(
            name='Department of Computer Science & Engineering',
            unit_type='DEPARTMENT',
            head=self.hod_cse
        )
        self.dept_ece = OrganizingUnit.objects.create(
            name='Department of Electronics & Communication Engineering',
            unit_type='DEPARTMENT',
            head=self.hod_ece
        )

        self.client = Client()

    # --- Fix #1: Unauthenticated & Non-Superuser Switcher Takeover ---
    def test_unauthenticated_public_home_showcase(self):
        """
        Requirement 2: Unauthenticated visitors see public event discovery
        with minimal description and prominent top-right Sign In button.
        """
        now = timezone.now()
        EventProposal.objects.create(
            title='Annual Technical Conclave',
            description='National research symposium',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            start_date=now + timedelta(days=2),
            end_date=now + timedelta(days=3),
            requested_budget=25000,
            approved_budget=25000,
            venue='Auditorium 1',
            status='APPROVED'
        )
        res = self.client.get('/')
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, 'INSTITUTE OF TECHNOLOGY AND MANAGEMENT')
        self.assertContains(res, 'Sign In')
        self.assertContains(res, 'Annual Technical Conclave')
        self.assertContains(res, 'Sign In to Register')

    def test_authenticated_student_can_visit_public_landing_home(self):
        """
        Fix: Authenticated student or faculty visiting '/' sees the college events
        landing page rather than being forced directly into the student dashboard.
        """
        self.client.login(username='student1', password='password123')
        res = self.client.get('/')
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, 'Campus Events &amp; Symposia')
        self.assertContains(res, 'INSTITUTE OF TECHNOLOGY AND MANAGEMENT')

    def test_switch_user_unauthenticated_blocked(self):
        """Fix #1: Unauthenticated user cannot switch to admin or other accounts."""
        res = self.client.get('/switch/admin/')
        self.assertNotEqual(res.status_code, 200)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/login/', res.url)

    @override_settings(DEBUG=True)
    def test_switch_user_regular_student_blocked(self):
        """Fix #1: Regular student account cannot switch accounts."""
        self.client.login(username='student1', password='password123')
        res = self.client.get('/switch/admin/')
        # Should raise PermissionDenied (HTTP 403)
        self.assertEqual(res.status_code, 403)
        # Verify student is still student1, not admin
        self.assertEqual(int(self.client.session['_auth_user_id']), self.student1.id)

    @override_settings(DEBUG=True)
    def test_superadmin_persistent_persona_switching_without_logout(self):
        """
        Requirement 4: Superadmin logs in once and can switch across multiple accounts
        (faculty -> hod -> student) without having to log out every time.
        """
        # 1. Login as admin
        self.client.login(username='admin', password='password123')

        # 2. Switch to faculty
        res1 = self.client.get('/switch/faculty_user/')
        self.assertEqual(res1.status_code, 302)
        self.assertEqual(int(self.client.session['_auth_user_id']), self.faculty.id)

        # 3. Switch directly to HOD CSE without logging off
        res2 = self.client.get('/switch/hod_cse_user/')
        self.assertEqual(res2.status_code, 302)
        self.assertEqual(int(self.client.session['_auth_user_id']), self.hod_cse.id)

        # 4. Switch directly to Student 1 without logging off
        res3 = self.client.get('/switch/student1/')
        self.assertEqual(res3.status_code, 302)
        self.assertEqual(int(self.client.session['_auth_user_id']), self.student1.id)

    # --- Fix #3: Static QR Token Replay ---
    def test_qr_static_token_replay_rejected(self):
        """Fix #3: Raw static UUID token without rotating timestamp and signature is rejected."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='HackFest 2026',
            description='Tech event',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            start_date=now + timedelta(days=1),
            end_date=now + timedelta(days=2),
            requested_budget=20000,
            approved_budget=20000,
            venue='Hall A',
            status='APPROVED'
        )
        # Attempt validate with raw static token
        is_valid, msg = proposal.validate_rotating_token(str(proposal.qr_checkin_token))
        self.assertFalse(is_valid)

    # --- Fix #4: IDOR Protection on Proposal, Compliance, and Public Views ---
    def test_idor_proposal_detail_blocked_for_student(self):
        """Fix #4: Student accessing internal proposal detail returns 404 (no leak)."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='Confidential Faculty Proposal',
            description='Private specs',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            start_date=now + timedelta(days=1),
            end_date=now + timedelta(days=2),
            requested_budget=50000,
            approved_budget=50000,
            venue='Board Room',
            status='UNDER_REVIEW'
        )
        self.client.login(username='student1', password='password123')
        res = self.client.get(f'/proposals/{proposal.id}/')
        self.assertEqual(res.status_code, 404)

    def test_idor_compliance_report_blocked_for_student(self):
        """Fix #4: Student accessing compliance report returns 404."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='Completed Event',
            description='Completed specs',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            start_date=now - timedelta(days=2),
            end_date=now - timedelta(days=1),
            requested_budget=50000,
            approved_budget=50000,
            venue='Hall B',
            status='COMPLETED'
        )
        self.client.login(username='student1', password='password123')
        res = self.client.get(f'/proposals/{proposal.id}/compliance-report/')
        self.assertEqual(res.status_code, 404)

    def test_idor_draft_event_public_detail_blocked(self):
        """Fix #4: Public detail view returns 404 for non-approved proposal to regular students."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='Under Review Draft',
            description='Draft',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            start_date=now + timedelta(days=3),
            end_date=now + timedelta(days=4),
            requested_budget=10000,
            approved_budget=10000,
            venue='Hall C',
            status='UNDER_REVIEW'
        )
        self.client.login(username='student1', password='password123')
        res = self.client.get(f'/events/{proposal.id}/details/')
        self.assertEqual(res.status_code, 404)

    # --- Fix #6: Feedback Gate Enforced ---
    def test_feedback_without_check_in_blocked(self):
        """Fix #6: Student who registered but never checked in cannot submit feedback."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='Webinar on Quantum Computing',
            description='Webinar',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            start_date=now + timedelta(days=2),
            end_date=now + timedelta(days=3),
            requested_budget=15000,
            approved_budget=15000,
            venue='Virtual',
            status='APPROVED'
        )
        reg = EventRegistration.objects.create(
            event=proposal,
            student=self.student1,
            role='PARTICIPANT',
            status='REGISTERED'  # NOT CHECKED_IN!
        )
        self.client.login(username='student1', password='password123')
        res = self.client.post(f'/registrations/{reg.id}/feedback/', {
            'rating_overall': 5,
            'rating_content': 5,
            'rating_speaker': 5,
            'comments': 'Bypassing checkin?'
        })
        reg.refresh_from_db()
        self.assertEqual(reg.status, 'REGISTERED')
        self.assertFalse(hasattr(reg, 'feedback'))

    # --- Fix #7: HOD Cross-Department Privilege Escalation ---
    def test_hod_cross_dept_escalation_blocked(self):
        """Fix #7: ECE HOD cannot approve CSE department event."""
        now = timezone.now()
        chain = [{'role': 'HOD', 'title': 'HOD Approval', 'step': 1, 'status': 'PENDING'}]
        proposal = EventProposal.objects.create(
            title='CSE Department Workshop',
            description='CSE only',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            chain_type='ACADEMIC',
            approval_chain=chain,
            current_stage_index=0,
            requested_budget=25000,
            approved_budget=25000,
            start_date=now + timedelta(days=5),
            end_date=now + timedelta(days=6),
            venue='CSE Lab 1',
            status='UNDER_REVIEW'
        )
        # HOD of ECE attempts to approve CSE proposal
        self.assertFalse(proposal.is_awaiting_user(self.hod_ece))
        self.assertTrue(proposal.is_awaiting_user(self.hod_cse))

    # --- Fix #8: REVISE_BUDGET Inverted Logic & Authorization ---
    def test_revise_budget_non_dean_blocked(self):
        """Fix #8: Non-Dean of Accounts cannot invoke REVISE_BUDGET."""
        now = timezone.now()
        chain = [{'role': 'HOD', 'title': 'HOD Approval', 'step': 1, 'status': 'PENDING'}]
        proposal = EventProposal.objects.create(
            title='Robotics Lab Fund',
            description='Hardware',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            chain_type='ACADEMIC',
            approval_chain=chain,
            current_stage_index=0,
            requested_budget=80000,
            approved_budget=80000,
            start_date=now + timedelta(days=5),
            end_date=now + timedelta(days=6),
            venue='Robo Lab',
            status='UNDER_REVIEW'
        )
        self.client.login(username='hod_cse_user', password='password123')
        res = self.client.post(f'/proposals/{proposal.id}/action/', {
            'action': 'REVISE_BUDGET',
            'new_budget': 50000,
            'remarks': 'HOD attempting budget revision'
        })
        self.assertEqual(res.status_code, 403)

    # --- Fix #9: Poster XSS & Size Validation ---
    def test_poster_preset_xss_blocked(self):
        """Fix #9: Malicious poster preset strings are rejected."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='Cyber Security Seminar',
            description='Security',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            requested_budget=20000,
            approved_budget=20000,
            start_date=now + timedelta(days=5),
            end_date=now + timedelta(days=6),
            venue='Auditorium',
            status='APPROVED_PENDING_PUBLISH'
        )
        self.client.login(username='faculty_user', password='password123')
        res = self.client.post(f'/proposals/{proposal.id}/publish/', {
            'poster_preset': 'x" onerror="alert(1)'
        })
        proposal.refresh_from_db()
        self.assertNotEqual(proposal.status, 'APPROVED')

    # --- Fix #10 & #24: Logistics Notification Uniqueness ---
    def test_logistics_notification_duplicates_prevented(self):
        """Fix #10 & #24: Multiple logistics dispatch triggers do not duplicate records."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='Mega Symposium',
            description='Annual Symposium',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            requested_budget=100000,
            approved_budget=100000,
            start_date=now + timedelta(days=7),
            end_date=now + timedelta(days=8),
            venue='Convention Center',
            mess_requirements='Catering for 200 delegates',
            status='APPROVED_PENDING_PUBLISH'
        )
        # Dispatch logistics twice
        dispatch_logistics_notifications(proposal)
        dispatch_logistics_notifications(proposal)
        count = LogisticsNotification.objects.filter(proposal=proposal, logistics_type='MESS').count()
        self.assertEqual(count, 1)

    # --- Fix #12: Logout via GET Blocked ---
    def test_logout_via_get_blocked(self):
        """Fix #12: GET /logout/ returns 405 Method Not Allowed."""
        self.client.login(username='student1', password='password123')
        res = self.client.get('/logout/')
        self.assertEqual(res.status_code, 405)

    # --- Fix #14: Proposal Input Validation ---
    def test_proposal_validation_empty_title_rejected(self):
        """Fix #14: Proposal with whitespace/empty title is rejected."""
        self.client.login(username='faculty_user', password='password123')
        res = self.client.post('/proposals/new/', {
            'title': '   ',
            'organizing_unit': self.dept_cse.id,
            'requested_budget': '5000',
            'start_date': '2026-11-20T10:00',
            'end_date': '2026-11-20T12:00',
            'expected_attendees': '50'
        })
        self.assertEqual(EventProposal.objects.filter(organizing_unit=self.dept_cse, requested_budget=5000).count(), 0)

    def test_proposal_validation_negative_budget_rejected(self):
        """Fix #14: Proposal with negative or zero budget is rejected."""
        self.client.login(username='faculty_user', password='password123')
        res = self.client.post('/proposals/new/', {
            'title': 'Negative Budget Event',
            'organizing_unit': self.dept_cse.id,
            'requested_budget': '-5000',
            'start_date': '2026-11-20T10:00',
            'end_date': '2026-11-20T12:00',
            'expected_attendees': '50'
        })
        self.assertEqual(EventProposal.objects.filter(title='Negative Budget Event').count(), 0)

    def test_proposal_validation_end_before_start_rejected(self):
        """Fix #14: Proposal with end date before start date is rejected."""
        self.client.login(username='faculty_user', password='password123')
        res = self.client.post('/proposals/new/', {
            'title': 'Invalid Dates Event',
            'organizing_unit': self.dept_cse.id,
            'requested_budget': '5000',
            'start_date': '2026-11-20T14:00',
            'end_date': '2026-11-20T10:00',
            'expected_attendees': '50'
        })
        self.assertEqual(EventProposal.objects.filter(title='Invalid Dates Event').count(), 0)

    # --- Fix #15: Registration Checks on Status, Capacity, Dates ---
    def test_registration_on_draft_event_blocked(self):
        """Fix #15: Students cannot register for DRAFT / UNDER_REVIEW events."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='Unapproved Event',
            description='Not approved yet',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            requested_budget=20000,
            approved_budget=20000,
            start_date=now + timedelta(days=2),
            end_date=now + timedelta(days=3),
            venue='Hall D',
            status='UNDER_REVIEW'
        )
        self.client.login(username='student1', password='password123')
        res = self.client.post(f'/events/{proposal.id}/register/', {'role': 'PARTICIPANT'})
        self.assertEqual(EventRegistration.objects.filter(event=proposal, student=self.student1).count(), 0)

    def test_registration_on_full_event_blocked(self):
        """Fix #15: Student cannot register for an event that has reached full capacity."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='Limited Capacity Workshop',
            description='Max 1 student',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            requested_budget=10000,
            approved_budget=10000,
            start_date=now + timedelta(days=2),
            end_date=now + timedelta(days=3),
            venue='Small Room',
            expected_attendees=1,
            status='APPROVED'
        )
        # student1 fills the single seat
        EventRegistration.objects.create(event=proposal, student=self.student1, role='PARTICIPANT')

        # student2 attempts to register
        self.client.login(username='student2', password='password123')
        res = self.client.post(f'/events/{proposal.id}/register/', {'role': 'PARTICIPANT'})
        self.assertEqual(EventRegistration.objects.filter(event=proposal, student=self.student2).count(), 0)

    def test_registration_on_past_event_blocked(self):
        """Fix #15: Student cannot register for an event that has already ended."""
        now = timezone.now()
        proposal = EventProposal.objects.create(
            title='Past Event',
            description='Already over',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            requested_budget=10000,
            approved_budget=10000,
            start_date=now - timedelta(days=4),
            end_date=now - timedelta(days=2),
            venue='Hall E',
            status='APPROVED'
        )
        self.client.login(username='student1', password='password123')
        res = self.client.post(f'/events/{proposal.id}/register/', {'role': 'PARTICIPANT'})
        self.assertEqual(EventRegistration.objects.filter(event=proposal, student=self.student1).count(), 0)

    # --- Fix #18: Custom Approval Chain Role Whitelist Injection ---
    def test_custom_approval_chain_injection_blocked(self):
        """Fix #18: Injecting unknown/unwhitelisted role names raises ValueError."""
        with self.assertRaises(ValueError):
            get_default_chain('CUSTOM', unit_id=self.dept_cse.id, custom_roles=['HOD_CSE', 'FAKE_INJECTED_ROLE'])

    # --- Fix #20: Unknown Action Fails Closed ---
    def test_unknown_action_fails_closed(self):
        """Fix #20: Unknown approval action fails closed with error."""
        now = timezone.now()
        chain = [{'role': 'HOD_CSE', 'title': 'HOD Approval', 'step': 1, 'status': 'PENDING'}]
        proposal = EventProposal.objects.create(
            title='Test Proposal',
            description='Test',
            proposer=self.faculty,
            organizing_unit=self.dept_cse,
            chain_type='ACADEMIC',
            approval_chain=chain,
            current_stage_index=0,
            requested_budget=10000,
            approved_budget=10000,
            start_date=now + timedelta(days=5),
            end_date=now + timedelta(days=6),
            venue='Hall F',
            status='UNDER_REVIEW'
        )
        self.client.login(username='hod_cse_user', password='password123')
        res = self.client.post(f'/proposals/{proposal.id}/action/', {
            'action': 'UNKNOWN_MALICIOUS_ACTION',
            'remarks': 'Testing unknown'
        })
        proposal.refresh_from_db()
        self.assertEqual(proposal.current_stage_index, 0)
        self.assertEqual(proposal.status, 'UNDER_REVIEW')

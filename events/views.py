import io
import json
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from PIL import Image

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.db import transaction
from django.db.models import Avg, Count, Q, Sum
from django.http import JsonResponse, HttpResponseForbidden, Http404

from .models import (
    UserProfile, OrganizingUnit, EventProposal,
    ApprovalLog, EventRegistration, EventFeedback, LogisticsNotification
)
from .utils import generate_qr_base64, dispatch_logistics_notifications, get_default_chain


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    next_url = request.GET.get('next') or request.POST.get('next') or ''

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Requirement 4: Mark superadmin session so persona switching persists without logging off
            if user.is_superuser:
                request.session['is_superadmin_session'] = True
                request.session['original_superadmin_id'] = user.id
            if next_url and next_url != '/login/':
                return redirect(next_url)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, 'registration/login.html', {'next': next_url})


@require_POST
def logout_view(request):
    """Fix #12: Logout via POST strictly to prevent CSRF logout attacks."""
    request.session.flush()
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('home')


@login_required
def switch_user_view(request, username):
    """
    Requirement 4: Once superadmin logs in, they have persistent access to switch to all
    demo accounts without being logged out every time. Other entities who log in directly
    do NOT have access to switch accounts.
    """
    is_superadmin_session = request.user.is_superuser or request.session.get('is_superadmin_session', False)
    if not is_superadmin_session:
        raise PermissionDenied("Access Denied: Only a verified Superadmin session is authorized to switch presentation personas.")

    if not settings.DEBUG:
        raise PermissionDenied("Account switching is only permitted in debug demonstration mode.")

    original_admin_id = request.session.get('original_superadmin_id') or (request.user.id if request.user.is_superuser else None)

    target_user = get_object_or_404(User, username=username)
    login(request, target_user)

    # Persist the superadmin authorization flag in the newly rotated session
    request.session['is_superadmin_session'] = True
    request.session['original_superadmin_id'] = original_admin_id

    role_name = target_user.profile.get_role_display() if hasattr(target_user, 'profile') else 'User'
    messages.info(request, f"Switched presentation view to: {target_user.get_full_name() or target_user.username} ({role_name})")
    return redirect('dashboard')


def register_student_view(request):
    """
    Public student self-registration is disabled.
    All student accounts are pre-provisioned in the institutional database.
    """
    messages.warning(request, "Public self-registration is disabled. All student and faculty accounts are pre-provisioned by College IT Administration.")
    return redirect('login')


def public_home_view(request):
    """
    Public Campus Events Landing Page.
    Always displays the public event discovery showcase with minimal descriptions,
    dates, venues, keynote speakers, and registration action buttons.
    Accessible to everyone (visitors & authenticated users alike).
    """
    published_events = EventProposal.objects.filter(status__in=['APPROVED', 'COMPLETED']).order_by('start_date')
    return render(request, 'events/public_home.html', {'events': published_events})


@login_required
def dashboard_view(request):
    """
    Internal role-specific dashboard:
    - Students: Registered events, selfie verification status, feedback certificates.
    - Faculty/HOD/Deans/Director: Proposal submission, review chains, logistics dispatch.
    """
    user = request.user
    profile = getattr(user, 'profile', None)
    role = profile.role if profile else 'STUDENT'

    # --- 1. DEDICATED STUDENT DASHBOARD ---
    if role == 'STUDENT':
        registrations = EventRegistration.objects.filter(student=user).select_related('event', 'event__organizing_unit').order_by('-registered_at')
        verified_count = registrations.filter(status='VERIFIED').count()
        checked_in_count = registrations.filter(status='CHECKED_IN').count()

        upcoming_events = EventProposal.objects.filter(status__in=['APPROVED', 'COMPLETED']).order_by('start_date')[:6]

        context = {
            'is_student': True,
            'role': 'STUDENT',
            'profile': profile,
            'registrations': registrations,
            'verified_count': verified_count,
            'checked_in_count': checked_in_count,
            'upcoming_events': upcoming_events,
        }
        return render(request, 'events/dashboard.html', context)

    # --- 2. FACULTY, APPROVER & EXECUTIVE DASHBOARD ---
    my_proposals = EventProposal.objects.filter(proposer=user).order_by('-created_at')

    all_under_review = EventProposal.objects.filter(status='UNDER_REVIEW').order_by('-updated_at')
    pending_approvals = [p for p in all_under_review if p.is_awaiting_user(user)]

    all_approved = EventProposal.objects.filter(status__in=['APPROVED', 'COMPLETED']).order_by('-start_date')[:6]
    total_sanctioned_budget = EventProposal.objects.filter(status__in=['APPROVED', 'APPROVED_PENDING_PUBLISH', 'COMPLETED']).aggregate(Sum('approved_budget'))['approved_budget__sum'] or 0

    context = {
        'is_student': False,
        'role': role,
        'profile': profile,
        'my_proposals': my_proposals,
        'pending_approvals': pending_approvals,
        'all_approved': all_approved,
        'stats': {
            'total_proposals': EventProposal.objects.count(),
            'approved_count': EventProposal.objects.filter(status='APPROVED').count(),
            'pending_publish_count': EventProposal.objects.filter(status='APPROVED_PENDING_PUBLISH').count(),
            'revision_count': EventProposal.objects.filter(status='REVISION_REQUESTED').count(),
            'total_students': UserProfile.objects.filter(role='STUDENT').count(),
            'total_budget_sanctioned': total_sanctioned_budget,
        }
    }
    return render(request, 'events/dashboard.html', context)


@login_required
def create_proposal_view(request):
    """
    Department-wise HOD approval chains with strict input validation (Fix #14).
    Students are strictly barred.
    """
    profile = getattr(request.user, 'profile', None)
    if not profile or profile.role == 'STUDENT':
        messages.error(request, "Access Denied: Students are not authorized to propose or publish college events.")
        return redirect('dashboard')

    units = OrganizingUnit.objects.all().order_by('name')

    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        description = request.POST.get('description', '').strip()
        unit_id = request.POST.get('organizing_unit')
        co_coordinator = request.POST.get('co_coordinator', '').strip()
        guest_speaker = request.POST.get('guest_speaker', '').strip()
        venue = request.POST.get('venue', '').strip()
        
        errors = []
        if not title:
            errors.append("Event title is required.")

        try:
            requested_budget = Decimal(str(request.POST.get('requested_budget', '')).strip())
            if requested_budget <= 0 or requested_budget > Decimal('9999999999.99'):
                raise ValueError
        except (InvalidOperation, ValueError):
            errors.append("Invalid requested budget. Amount must be positive and within institutional limits.")
            requested_budget = Decimal('0.00')

        try:
            expected_attendees = int(request.POST.get('expected_attendees', 100))
            if expected_attendees <= 0 or expected_attendees > 100000:
                raise ValueError
        except ValueError:
            errors.append("Invalid expected attendee count.")
            expected_attendees = 100

        start_date_str = request.POST.get('start_date')
        end_date_str = request.POST.get('end_date')
        start_date = parse_datetime(start_date_str) if start_date_str else None
        end_date = parse_datetime(end_date_str) if end_date_str else None

        if not start_date or not end_date:
            try:
                start_date = datetime.fromisoformat(start_date_str) if start_date_str else None
                end_date = datetime.fromisoformat(end_date_str) if end_date_str else None
            except Exception:
                pass

        if not start_date or not end_date:
            errors.append("Valid start and end dates are required.")
        elif end_date <= start_date:
            errors.append("End date and time must be strictly after the start date and time.")

        if errors:
            for err in errors:
                messages.error(request, err)
            return render(request, 'events/proposal_form.html', {'units': units, 'is_edit': False})

        # Department-Specific Approval Chain Selection & Whitelist Validation (Fix #18)
        chain_type = request.POST.get('chain_type', 'ACADEMIC')
        custom_roles = request.POST.getlist('custom_roles') if chain_type == 'CUSTOM' else None
        try:
            chain_list = get_default_chain(chain_type, unit_id=unit_id, custom_roles=custom_roles)
        except ValueError as e:
            messages.error(request, str(e))
            return render(request, 'events/proposal_form.html', {'units': units, 'is_edit': False})

        mess_req = request.POST.get('mess_requirements', '')
        transport_req = request.POST.get('transport_requirements', '')
        maint_req = request.POST.get('maintenance_requirements', '')

        unit = get_object_or_404(OrganizingUnit, id=unit_id)

        proposal = EventProposal.objects.create(
            title=title,
            description=description,
            proposer=request.user,
            organizing_unit=unit,
            co_coordinator=co_coordinator,
            guest_speaker=guest_speaker,
            requested_budget=requested_budget,
            approved_budget=requested_budget,
            start_date=start_date,
            end_date=end_date,
            venue=venue,
            expected_attendees=expected_attendees,
            chain_type=chain_type,
            approval_chain=chain_list,
            current_stage_index=0,
            mess_requirements=mess_req,
            transport_requirements=transport_req,
            maintenance_requirements=maint_req,
            status='UNDER_REVIEW'
        )

        first_stage = proposal.current_stage
        stage_title = first_stage.get('title', 'Stage 1') if first_stage else 'Stage 1'
        messages.success(request, f"Event proposal '{proposal.title}' filed! Routed to Stage 1: {stage_title}.")
        return redirect('proposal_detail', proposal_id=proposal.id)

    return render(request, 'events/proposal_form.html', {'units': units, 'is_edit': False})


@login_required
def edit_proposal_view(request, proposal_id):
    """
    Fix #14 & #19:
    Allows proposer to fix remarks and resubmit proposal through the full chain from Stage 1.
    Preserves approved_budget and rebuilds approval_chain if missing.
    """
    proposal = get_object_or_404(EventProposal, id=proposal_id, proposer=request.user)
    if proposal.status != 'REVISION_REQUESTED':
        messages.warning(request, "This proposal is not currently marked for revision.")
        return redirect('proposal_detail', proposal_id=proposal.id)

    units = OrganizingUnit.objects.all().order_by('name')

    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        if not title:
            messages.error(request, "Event title is required.")
            return render(request, 'events/proposal_form.html', {'proposal': proposal, 'units': units, 'is_edit': True, 'latest_log': proposal.logs.first()})

        proposal.title = title
        proposal.description = request.POST.get('description', '').strip()
        unit_id = request.POST.get('organizing_unit')
        proposal.organizing_unit = get_object_or_404(OrganizingUnit, id=unit_id)
        proposal.co_coordinator = request.POST.get('co_coordinator', '').strip()
        proposal.guest_speaker = request.POST.get('guest_speaker', '').strip()
        proposal.venue = request.POST.get('venue', '').strip()

        try:
            req_budget = Decimal(str(request.POST.get('requested_budget', proposal.requested_budget)).strip())
            if req_budget <= 0 or req_budget > Decimal('9999999999.99'):
                raise ValueError
            proposal.requested_budget = req_budget
        except (InvalidOperation, ValueError):
            messages.error(request, "Invalid requested budget.")
            return render(request, 'events/proposal_form.html', {'proposal': proposal, 'units': units, 'is_edit': True, 'latest_log': proposal.logs.first()})

        # Preserve approved_budget (Fix #14)
        if not proposal.approved_budget:
            proposal.approved_budget = proposal.requested_budget

        try:
            attendees = int(request.POST.get('expected_attendees', 100))
            if attendees <= 0 or attendees > 100000:
                raise ValueError
            proposal.expected_attendees = attendees
        except ValueError:
            messages.error(request, "Invalid expected attendee count.")
            return render(request, 'events/proposal_form.html', {'proposal': proposal, 'units': units, 'is_edit': True, 'latest_log': proposal.logs.first()})

        start_date_str = request.POST.get('start_date')
        end_date_str = request.POST.get('end_date')
        start_date = parse_datetime(start_date_str) if start_date_str else None
        end_date = parse_datetime(end_date_str) if end_date_str else None

        if not start_date or not end_date:
            try:
                start_date = datetime.fromisoformat(start_date_str) if start_date_str else None
                end_date = datetime.fromisoformat(end_date_str) if end_date_str else None
            except Exception:
                pass

        if start_date and end_date and end_date > start_date:
            proposal.start_date = start_date
            proposal.end_date = end_date

        proposal.mess_requirements = request.POST.get('mess_requirements', '')
        proposal.transport_requirements = request.POST.get('transport_requirements', '')
        proposal.maintenance_requirements = request.POST.get('maintenance_requirements', '')

        new_chain_type = request.POST.get('chain_type', proposal.chain_type)
        if new_chain_type != proposal.chain_type or new_chain_type == 'CUSTOM' or not proposal.approval_chain:
            custom_roles = request.POST.getlist('custom_roles') if new_chain_type == 'CUSTOM' else None
            proposal.chain_type = new_chain_type
            proposal.approval_chain = get_default_chain(new_chain_type, unit_id=unit_id, custom_roles=custom_roles)
        else:
            for idx, st in enumerate(proposal.approval_chain, start=1):
                st['status'] = 'PENDING' if idx == 1 else 'WAITING'

        proposal.status = 'UNDER_REVIEW'
        proposal.current_stage_index = 0
        proposal.revision_count += 1
        proposal.is_revision = True
        proposal.save()

        ApprovalLog.objects.create(
            proposal=proposal,
            approver=request.user,
            stage_name=f'Resubmission (Revision Cycle {proposal.revision_count})',
            action='APPROVED',
            remarks=request.POST.get('resubmission_notes', 'Addressed revision remarks and resubmitted to approval chain.'),
            revision_cycle=proposal.revision_count
        )

        messages.success(request, f"Proposal updated and re-routed to Stage 1 marked as 'Revision Cycle {proposal.revision_count}'.")
        return redirect('proposal_detail', proposal_id=proposal.id)

    return render(request, 'events/proposal_form.html', {
        'proposal': proposal,
        'units': units,
        'is_edit': True,
        'latest_log': proposal.logs.first()
    })


@login_required
def proposal_detail_view(request, proposal_id):
    """
    Fix #4: IDOR Protection.
    Only the proposer, designated reviewers, superusers, or institutional heads can view details.
    Unauthorized users receive a 404 response to prevent sequential ID enumeration.
    """
    proposal = get_object_or_404(EventProposal, id=proposal_id)
    is_approver = proposal.is_awaiting_user(request.user)
    is_proposer = (proposal.proposer == request.user)

    user_role = getattr(request.user.profile, 'role', None) if hasattr(request.user, 'profile') else None
    is_authorized_authority = user_role in ['HOD', 'DEAN_ACCOUNTS', 'DEAN_ACADEMICS', 'DEAN_RESEARCH', 'DEAN_STUDENT_WELFARE', 'DIRECTOR', 'REGISTRAR'] and (
        proposal.organizing_unit.head == request.user or user_role in ['DEAN_ACCOUNTS', 'DEAN_ACADEMICS', 'DIRECTOR'] or any(log.approver == request.user for log in proposal.logs.all())
    )

    if not (is_proposer or is_approver or request.user.is_superuser or is_authorized_authority):
        raise Http404("Proposal not found")

    logs = proposal.logs.all().order_by('-created_at')
    logistics = proposal.logistics_notifications.all()

    chain = proposal.approval_chain or []
    current_index = proposal.current_stage_index

    stages = []
    for idx, st in enumerate(chain):
        step_num = idx + 1
        if proposal.status in ['APPROVED', 'APPROVED_PENDING_PUBLISH', 'COMPLETED']:
            status = 'CLEARED'
        elif proposal.status == 'UNDER_REVIEW':
            if idx < current_index:
                status = 'CLEARED'
            elif idx == current_index:
                status = 'CURRENT'
            else:
                status = 'WAITING'
        else:
            status = 'STOPPED' if idx == current_index else 'WAITING'

        stages.append({
            'step': step_num,
            'role': st.get('role'),
            'title': st.get('title'),
            'status': status,
        })

    all_registrations = proposal.registrations.all().select_related('student', 'student__profile', 'feedback').order_by('-registered_at')
    attended_students = [r for r in all_registrations if r.status in ['CHECKED_IN', 'VERIFIED']]
    verified_students = [r for r in all_registrations if r.status == 'VERIFIED']

    roster_stats = {
        'total_registered': len(all_registrations),
        'total_attended': len(attended_students),
        'total_verified': len(verified_students),
        'turnout_pct': round((len(attended_students) / len(all_registrations) * 100), 1) if all_registrations else 0,
    }

    context = {
        'proposal': proposal,
        'is_approver': is_approver,
        'is_proposer': is_proposer,
        'logs': logs,
        'logistics': logistics,
        'stages': stages,
        'current_stage_num': current_index + 1,
        'total_stages': len(chain),
        'user_role': user_role or 'STUDENT',
        'all_registrations': all_registrations,
        'attended_students': attended_students,
        'roster_stats': roster_stats,
    }
    return render(request, 'events/proposal_detail.html', context)


@login_required
def process_approval_view(request, proposal_id):
    """
    Fix #8: Strict profile guard, Decimal precision, and correct authorization check on REVISE_BUDGET.
    Fix #20: Fail closed on unknown action with explicit error message.
    """
    if request.method != 'POST':
        return redirect('proposal_detail', proposal_id=proposal_id)

    proposal = get_object_or_404(EventProposal, id=proposal_id)
    if not proposal.is_awaiting_user(request.user):
        messages.error(request, "You do not have authorization to approve at this stage.")
        return redirect('proposal_detail', proposal_id=proposal_id)

    action = request.POST.get('action')
    remarks = request.POST.get('remarks', '').strip()
    profile = getattr(request.user, 'profile', None)
    user_role = profile.role if profile else None

    if action in ['REJECT', 'REQUEST_REVISION'] and not remarks:
        messages.error(request, "Written remarks are mandatory when requesting a revision or rejecting.")
        return redirect('proposal_detail', proposal_id=proposal_id)

    chain = proposal.approval_chain or []
    current_idx = proposal.current_stage_index
    current_stage_dict = chain[current_idx] if current_idx < len(chain) else {}
    current_stage_title = current_stage_dict.get('title', f"Stage {current_idx + 1}")

    if action == 'APPROVE':
        current_stage_dict['status'] = 'APPROVED'
        ApprovalLog.objects.create(
            proposal=proposal,
            approver=request.user,
            stage_name=current_stage_title,
            action='APPROVED',
            remarks=remarks or "Approved without additional stipulations.",
            revision_cycle=proposal.revision_count
        )

        next_idx = current_idx + 1
        if next_idx >= len(chain):
            proposal.status = 'APPROVED_PENDING_PUBLISH'
            proposal.current_stage_index = next_idx
            proposal.save()
            dispatch_logistics_notifications(proposal)
            messages.success(request, f"Executive clearance granted! '{proposal.title}' is approved and logistics sections have been notified. It is now ready for the Faculty Coordinator to upload a poster and publish.")
        else:
            chain[next_idx]['status'] = 'PENDING'
            proposal.current_stage_index = next_idx
            proposal.approval_chain = chain
            proposal.save()
            next_stage_title = chain[next_idx].get('title', f"Stage {next_idx + 1}")
            messages.success(request, f"Approved! Proposal advanced to Stage {next_idx + 1}: {next_stage_title}.")

    elif action == 'REVISE_BUDGET':
        # Fix #8: Inverted logic fixed to OR - both user and stage must be DEAN_ACCOUNTS
        if user_role != 'DEAN_ACCOUNTS' or current_stage_dict.get('role') != 'DEAN_ACCOUNTS':
            return HttpResponseForbidden("Only the Dean of Finance & Accounts at the budget sanction stage can revise budgets.")

        try:
            new_budget = Decimal(str(request.POST.get('new_budget', '')).strip())
            if not (0 < new_budget <= Decimal('9999999999.99')):
                raise ValueError
        except (InvalidOperation, ValueError):
            messages.error(request, "Invalid budget amount provided.")
            return redirect('proposal_detail', proposal_id=proposal_id)

        old_budget = proposal.approved_budget
        proposal.approved_budget = new_budget
        proposal.budget_revision_reason = remarks

        current_stage_dict['status'] = 'APPROVED'
        ApprovalLog.objects.create(
            proposal=proposal,
            approver=request.user,
            stage_name=current_stage_title,
            action='BUDGET_REVISED',
            old_budget=old_budget,
            revised_budget=new_budget,
            remarks=remarks or f"Budget adjusted from ₹{old_budget} to ₹{new_budget}.",
            revision_cycle=proposal.revision_count
        )

        next_idx = current_idx + 1
        if next_idx >= len(chain):
            proposal.status = 'APPROVED_PENDING_PUBLISH'
            proposal.current_stage_index = next_idx
            proposal.save()
            dispatch_logistics_notifications(proposal)
        else:
            chain[next_idx]['status'] = 'PENDING'
            proposal.current_stage_index = next_idx
            proposal.approval_chain = chain
            proposal.save()

        messages.success(request, f"Budget revised to ₹{new_budget:,.2f}. Proposal advanced to next stage.")

    elif action == 'REQUEST_REVISION':
        current_stage_dict['status'] = 'REVISION_REQUESTED'
        proposal.status = 'REVISION_REQUESTED'
        proposal.approval_chain = chain
        proposal.save()

        ApprovalLog.objects.create(
            proposal=proposal,
            approver=request.user,
            stage_name=current_stage_title,
            action='REVISION_REQUESTED',
            remarks=remarks,
            revision_cycle=proposal.revision_count
        )
        messages.warning(request, f"Proposal returned for revision to {proposal.proposer.get_full_name() or proposal.proposer.username}.")

    elif action == 'REJECT':
        current_stage_dict['status'] = 'REJECTED'
        proposal.status = 'REJECTED'
        proposal.approval_chain = chain
        proposal.save()

        ApprovalLog.objects.create(
            proposal=proposal,
            approver=request.user,
            stage_name=current_stage_title,
            action='REJECTED',
            remarks=remarks,
            revision_cycle=proposal.revision_count
        )
        messages.error(request, f"Proposal '{proposal.title}' was rejected.")

    else:
        # Fix #20: Fail closed on unknown action
        messages.error(request, f"Unknown approval action: '{action}'.")
        return redirect('proposal_detail', proposal_id=proposal_id)

    return redirect('proposal_detail', proposal_id=proposal_id)


# --- Faculty Poster Upload & Final Publish View ---

@login_required
def publish_event_view(request, proposal_id):
    """
    Fix #9: Poster XSS / Size validation and re-publish prevention.
    """
    proposal = get_object_or_404(EventProposal, id=proposal_id)
    if proposal.proposer != request.user and not request.user.is_superuser:
        messages.error(request, "Only the designated event coordinator can publish this event.")
        return redirect('proposal_detail', proposal_id=proposal.id)

    if proposal.status == 'APPROVED':
        messages.error(request, "Event is already published.")
        return redirect('proposal_detail', proposal_id=proposal.id)

    if proposal.status not in ['APPROVED_PENDING_PUBLISH']:
        messages.warning(request, "This proposal has not yet cleared all administrative approval stages.")
        return redirect('proposal_detail', proposal_id=proposal.id)

    if request.method == 'POST':
        poster_file = request.FILES.get('poster_file')
        poster_preset = request.POST.get('poster_preset', '').strip()

        # Regex allowlist validation for preset (Fix #9)
        ALLOWED_PRESET_RE = re.compile(r'^(preset_[a-z0-9_]{1,40}|data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+|https?:\/\/[a-zA-Z0-9_\-\.\/]+)$')
        if poster_preset and not ALLOWED_PRESET_RE.match(poster_preset):
            messages.error(request, "Invalid poster preset format.")
            return redirect('publish_event', proposal_id=proposal.id)

        # Upload file validation: max 5MB and valid image header (Fix #9)
        if poster_file:
            if poster_file.size > 5 * 1024 * 1024:
                messages.error(request, "Poster image must be under 5MB.")
                return redirect('publish_event', proposal_id=proposal.id)
            try:
                img = Image.open(poster_file)
                img.verify()
            except Exception:
                messages.error(request, "Invalid image file format.")
                return redirect('publish_event', proposal_id=proposal.id)
            proposal.poster_image = poster_file
        elif poster_preset:
            proposal.poster_data_uri = poster_preset

        proposal.status = 'APPROVED'
        proposal.published_at = timezone.now()
        proposal.save()

        messages.success(request, f"🎉 '{proposal.title}' is now officially published! The event is now live on the Student Campus Events portal for registrations.")
        return redirect('proposal_detail', proposal_id=proposal.id)

    return render(request, 'events/publish_event.html', {'proposal': proposal})


# --- Public / Campus Event Description View ---

def event_public_detail_view(request, proposal_id):
    """
    Requirement 2: Dedicated public/campus description view of the event.
    Non-approved proposals return 404 to non-organizers to prevent ID enumeration.
    Open to unauthenticated visitors for viewing; registration requires sign in.
    """
    proposal = get_object_or_404(EventProposal, id=proposal_id)
    if proposal.status not in ['APPROVED', 'COMPLETED']:
        if not request.user.is_authenticated or (proposal.proposer != request.user and not request.user.is_superuser):
            raise Http404("Event not found")

    user_registration = None
    is_student = False
    is_organizer = False

    if request.user.is_authenticated:
        user_registration = EventRegistration.objects.filter(event=proposal, student=request.user).first()
        is_student = hasattr(request.user, 'profile') and request.user.profile.role == 'STUDENT'
        is_organizer = (proposal.proposer == request.user)

    context = {
        'proposal': proposal,
        'user_registration': user_registration,
        'is_student': is_student,
        'is_organizer': is_organizer,
    }
    return render(request, 'events/event_public_detail.html', context)


# --- Student & Public Facing Event Views ---

def student_events_view(request):
    """Students, campus visitors, and entities browse approved & published events."""
    published_events = EventProposal.objects.filter(status__in=['APPROVED', 'COMPLETED']).order_by('start_date')

    user_registrations = {}
    if request.user.is_authenticated and hasattr(request.user, 'event_registrations'):
        for reg in request.user.event_registrations.all():
            user_registrations[reg.event_id] = reg

    context = {
        'events': published_events,
        'user_registrations': user_registrations,
    }
    return render(request, 'events/student_events.html', context)


@login_required
def event_register_view(request, proposal_id):
    """
    Fix #13 & #15:
    - Atomic transaction + select_for_update to eliminate registration race conditions.
    - Capacity enforcement and end-date check.
    - Single registration constraint per student.
    """
    proposal = get_object_or_404(EventProposal, id=proposal_id)

    if proposal.status != 'APPROVED':
        messages.error(request, "Event is not open for registration.")
        return redirect('event_public_detail', proposal_id=proposal.id)

    if proposal.end_date < timezone.now():
        messages.error(request, "Registration is closed - event has ended.")
        return redirect('event_public_detail', proposal_id=proposal.id)

    # Role check: only students register
    if not hasattr(request.user, 'profile') or request.user.profile.role != 'STUDENT':
        messages.error(request, "Only students can register for events. Faculty and institutional heads can view details.")
        return redirect('event_public_detail', proposal_id=proposal.id)

    if request.method == 'POST':
        with transaction.atomic():
            reg_count = EventRegistration.objects.select_for_update().filter(event=proposal).count()
            if reg_count >= proposal.expected_attendees:
                messages.error(request, "Event has reached maximum capacity.")
                return redirect('event_public_detail', proposal_id=proposal.id)

            existing_reg = EventRegistration.objects.select_for_update().filter(event=proposal, student=request.user).first()
            if existing_reg:
                messages.warning(request, f"You are already registered for '{proposal.title}' as a {existing_reg.get_role_display()}. Only one registration per student is allowed.")
                return redirect('event_public_detail', proposal_id=proposal.id)

            role = request.POST.get('role', 'PARTICIPANT')
            if role not in ['PARTICIPANT', 'VOLUNTEER', 'VIEWER']:
                role = 'PARTICIPANT'

            EventRegistration.objects.create(
                event=proposal,
                student=request.user,
                role=role,
                status='REGISTERED'
            )
            messages.success(request, f"Registration confirmed! You have registered as a {role.capitalize()} for '{proposal.title}'.")
            return redirect('event_public_detail', proposal_id=proposal.id)

    return redirect('event_public_detail', proposal_id=proposal.id)


@login_required
def my_registrations_view(request):
    registrations = EventRegistration.objects.filter(student=request.user).order_by('-registered_at')
    return render(request, 'events/my_registrations.html', {'registrations': registrations})


# --- Organizer-Only Live Rotating QR Screen ---

@login_required
def live_event_view(request, proposal_id):
    """
    Only the designated event coordinator can project live attendance QR.
    """
    proposal = get_object_or_404(EventProposal, id=proposal_id)

    if proposal.proposer != request.user and not request.user.is_superuser:
        messages.error(request, f"Access Denied: Only the designated event coordinator ({proposal.proposer.get_full_name() or proposal.proposer.username}) is authorized to project the live attendance QR code.")
        return redirect('proposal_detail', proposal_id=proposal.id)

    token, seconds_left = proposal.get_rotating_qr_token()
    checkin_url = request.build_absolute_uri(f"/events/checkin/?token={token}")
    qr_data_uri = generate_qr_base64(checkin_url)

    registrations = proposal.registrations.all().order_by('-checked_in_at')
    stats = {
        'total_registered': registrations.count(),
        'checked_in': registrations.filter(status__in=['CHECKED_IN', 'VERIFIED']).count(),
        'verified': registrations.filter(status='VERIFIED').count(),
    }

    context = {
        'proposal': proposal,
        'qr_data_uri': qr_data_uri,
        'checkin_url': checkin_url,
        'current_token': token,
        'seconds_left': seconds_left,
        'interval': proposal.ROTATION_INTERVAL,
        'registrations': registrations,
        'stats': stats,
    }
    return render(request, 'events/live_checkin.html', context)


@login_required
def rotating_qr_api_view(request, proposal_id):
    """API endpoint providing new rotating QR tokens strictly to organizer."""
    proposal = get_object_or_404(EventProposal, id=proposal_id)
    if proposal.proposer != request.user and not request.user.is_superuser:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    token, seconds_left = proposal.get_rotating_qr_token()
    checkin_url = request.build_absolute_uri(f"/events/checkin/?token={token}")
    qr_data_uri = generate_qr_base64(checkin_url)

    registrations = proposal.registrations.all()
    data = {
        'token': token,
        'seconds_left': seconds_left,
        'qr_data_uri': qr_data_uri,
        'total_registered': registrations.count(),
        'checked_in': registrations.filter(status__in=['CHECKED_IN', 'VERIFIED']).count(),
        'verified': registrations.filter(status='VERIFIED').count(),
    }
    return JsonResponse(data)


@login_required
def checkin_view(request):
    """
    Validates dynamic rotating QR token against expiration window.
    Applies atomic transaction and select_for_update (Fix #13).
    """
    token = request.GET.get('token') or request.POST.get('token') or ''
    proposal = None

    if token:
        base_token = token.rsplit('_', 2)[0] if '_' in token else token
        proposal = EventProposal.objects.filter(qr_checkin_token=base_token).first()

    if request.method == 'POST':
        token = request.POST.get('token', '').strip()
        selfie_b64 = request.POST.get('selfie_image', '')

        base_token = token.rsplit('_', 2)[0] if '_' in token else token
        proposal = get_object_or_404(EventProposal, qr_checkin_token=base_token)

        is_valid, reason = proposal.validate_rotating_token(token)
        if not is_valid:
            messages.error(request, f"❌ {reason}")
            return render(request, 'events/checkin_selfie.html', {'proposal': proposal, 'token': token, 'expired': True})

        with transaction.atomic():
            reg, _ = EventRegistration.objects.select_for_update().get_or_create(
                event=proposal,
                student=request.user,
                defaults={'role': 'PARTICIPANT', 'status': 'REGISTERED'}
            )
            reg.status = 'CHECKED_IN'
            reg.checked_in_at = timezone.now()
            reg.selfie_image = selfie_b64
            reg.save()

        messages.success(request, f"Check-in verified via live selfie! Please complete the quick mandatory feedback below to verify your attendance.")
        return redirect('event_feedback', registration_id=reg.id)

    context = {
        'proposal': proposal,
        'token': token,
        'expired': False,
    }
    return render(request, 'events/checkin_selfie.html', context)


@login_required
def feedback_view(request, registration_id):
    """
    Fix #6: Feedback Gate Enforced.
    Only students who have physically checked in (status == 'CHECKED_IN') can submit feedback.
    """
    reg = get_object_or_404(EventRegistration, id=registration_id, student=request.user)

    if hasattr(reg, 'feedback'):
        messages.info(request, "You have already completed feedback for this event.")
        return redirect('dashboard')

    if reg.status != 'CHECKED_IN':
        messages.error(request, "You must be checked in to submit feedback.")
        return redirect('event_public_detail', proposal_id=reg.event.id)

    if request.method == 'POST':
        try:
            rating_overall = max(1, min(5, int(request.POST.get('rating_overall', 5))))
            rating_content = max(1, min(5, int(request.POST.get('rating_content', 5))))
            rating_speaker = max(1, min(5, int(request.POST.get('rating_speaker', 5))))
        except (ValueError, TypeError):
            rating_overall = rating_content = rating_speaker = 5

        comments = request.POST.get('comments', '').strip()

        with transaction.atomic():
            EventFeedback.objects.create(
                registration=reg,
                rating_overall=rating_overall,
                rating_content=rating_content,
                rating_speaker=rating_speaker,
                comments=comments
            )
            reg.status = 'VERIFIED'
            reg.save()

        messages.success(request, "Dhanyavaad! Feedback received and your event attendance has been officially VERIFIED.")
        return redirect('dashboard')

    return render(request, 'events/feedback.html', {'registration': reg})


# --- Compliance & Audit Reporting ---

@login_required
def compliance_report_view(request, proposal_id):
    """
    Fix #4: IDOR Protection.
    Only the proposer, superuser, or institutional heads can view compliance reports.
    """
    proposal = get_object_or_404(EventProposal, id=proposal_id)
    user = request.user
    user_role = getattr(user.profile, 'role', None) if hasattr(user, 'profile') else None
    is_authorized = (
        proposal.proposer == user
        or user.is_superuser
        or user_role in ['DIRECTOR', 'DEAN_ACADEMICS', 'DEAN_ACCOUNTS', 'DEAN_RESEARCH']
        or (user_role == 'HOD' and proposal.organizing_unit.head == user)
    )
    if not is_authorized:
        raise Http404("Report not found")

    registrations = proposal.registrations.all()

    total_registered = registrations.count()
    total_checked_in = registrations.filter(status__in=['CHECKED_IN', 'VERIFIED']).count()
    total_verified = registrations.filter(status='VERIFIED').count()

    feedbacks = EventFeedback.objects.filter(registration__event=proposal)
    avg_ratings = feedbacks.aggregate(
        avg_overall=Avg('rating_overall'),
        avg_content=Avg('rating_content'),
        avg_speaker=Avg('rating_speaker'),
        total_count=Count('id')
    )

    budget_variance = proposal.approved_budget - proposal.requested_budget

    context = {
        'proposal': proposal,
        'registrations': registrations,
        'feedbacks': feedbacks,
        'stats': {
            'total_registered': total_registered,
            'total_checked_in': total_checked_in,
            'total_verified': total_verified,
            'attendance_rate': round((total_verified / total_registered * 100), 1) if total_registered > 0 else 0,
            'budget_variance': budget_variance,
            'avg_overall': round(avg_ratings['avg_overall'] or 0, 1),
            'avg_content': round(avg_ratings['avg_content'] or 0, 1),
            'avg_speaker': round(avg_ratings['avg_speaker'] or 0, 1),
            'feedback_count': avg_ratings['total_count'],
        },
        'logistics': proposal.logistics_notifications.all(),
        'approval_logs': proposal.logs.all().order_by('created_at'),
    }
    return render(request, 'events/compliance_report.html', context)


# --- Superadmin User & Entity Database Manager ---

@login_required
def superadmin_users_view(request):
    if not request.user.is_superuser:
        messages.error(request, "Access restricted to Superadministrator.")
        return redirect('dashboard')

    users = User.objects.all().select_related('profile').order_by('profile__role', 'username')
    return render(request, 'events/superadmin_users.html', {'managed_users': users})

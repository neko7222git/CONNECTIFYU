from django.conf import settings
from events.models import EventProposal


def demo_roles_processor(request):
    """
    Requirement 4:
    Provides authentic Indian college demo user accounts to superadmin sessions
    (and persists across persona switches during a superadmin session) in DEBUG mode.
    Regular entities logging in independently cannot access or view the switcher.
    Also provides institutional branding globally.
    """
    is_superadmin_session = request.user.is_authenticated and (
        request.user.is_superuser or request.session.get('is_superadmin_session', False)
    )

    demo_accounts = []
    if settings.DEBUG and is_superadmin_session:
        demo_accounts = [
            {'username': 'admin', 'label': 'Superadmin (IT Head)', 'name': 'Super Administrator', 'role': 'SUPERADMIN'},
            {'username': 'faculty', 'label': 'Faculty (CSE)', 'name': 'Prof. Rajesh Sharma', 'role': 'FACULTY'},
            {'username': 'faculty_ece', 'label': 'Faculty (ECE)', 'name': 'Dr. Arvind Swaminathan', 'role': 'FACULTY'},
            {'username': 'hod_cse', 'label': 'HOD (CSE)', 'name': 'Dr. K. V. Ramanathan', 'role': 'HOD'},
            {'username': 'hod_ece', 'label': 'HOD (ECE)', 'name': 'Dr. Sunita Kulkarni', 'role': 'HOD'},
            {'username': 'hod_mech', 'label': 'HOD (Mech)', 'name': 'Dr. Vikramaditya Rathore', 'role': 'HOD'},
            {'username': 'club_lead', 'label': 'Club Advisor', 'name': 'Prof. Priya Nair', 'role': 'CLUB_HEAD'},
            {'username': 'dean_finance', 'label': 'Dean (Finance)*', 'name': 'Dr. Suresh Chandra', 'role': 'DEAN_ACCOUNTS'},
            {'username': 'dean_academics', 'label': 'Dean (Academics)*', 'name': 'Dr. Meenakshi Sundaram', 'role': 'DEAN_ACADEMICS'},
            {'username': 'director', 'label': 'Director*', 'name': 'Dr. R. Chidambaram', 'role': 'DIRECTOR'},
            {'username': 'student1', 'label': 'Student 1 (CSE)', 'name': 'Aarav Patel', 'role': 'STUDENT'},
            {'username': 'student2', 'label': 'Student 2 (ECE)', 'name': 'Ananya Sen', 'role': 'STUDENT'},
        ]

    pending_count = 0
    if request.user.is_authenticated and hasattr(request.user, 'profile'):
        role = request.user.profile.role
        if role != 'STUDENT':
            all_proposals = EventProposal.objects.filter(status='UNDER_REVIEW').select_related('organizing_unit', 'proposer')
            pending_count = sum(1 for p in all_proposals if p.is_awaiting_user(request.user))

    return {
        'demo_accounts': demo_accounts,
        'is_superadmin_session': is_superadmin_session,
        'pending_approvals_count': pending_count,
        'institute_name': 'INSTITUTE OF TECHNOLOGY AND MANAGEMENT',
        'institute_short': 'ITM Gwalior',
        'institute_tagline': 'THINK BIG... THINK BEYOND',
        'institute_location': 'GWALIOR • MP • INDIA',
    }

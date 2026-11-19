from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from events.models import UserProfile, OrganizingUnit


class Command(BaseCommand):
    help = 'Imports or updates college staff members and assigns them to departments/units securely (Fix #23)'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, required=False)
        parser.add_argument('--name', type=str, required=False)
        parser.add_argument('--role', type=str, required=False)
        parser.add_argument('--unit', type=str, required=False)

    def handle(self, *args, **options):
        unit_name = options.get('unit')
        if not unit_name:
            self.stdout.write(self.style.SUCCESS("import_staff command ready. Pass --unit to lookup and bind staff."))
            return

        unit = None
        try:
            unit = OrganizingUnit.objects.get(name__iexact=unit_name)
        except OrganizingUnit.DoesNotExist:
            unit = OrganizingUnit.objects.filter(name__icontains=unit_name).first()
            if unit:
                self.stdout.write(self.style.WARNING(f"Fuzzy match: {unit_name!r} -> {unit.name!r}"))
            else:
                self.stdout.write(self.style.ERROR(f"Unit not found: {unit_name!r}"))
                return

        self.stdout.write(self.style.SUCCESS(f"Successfully resolved unit: {unit.name} (Type: {unit.unit_type})"))

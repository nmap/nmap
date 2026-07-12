"""Custom scan profile persistence."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from .models import ScanProfile
from .profiles import BUILT_IN_PROFILES
from .serialization import decode_profiles, encode_profiles, read_json_file, write_json_file
from .xdg_paths import custom_profiles_path


class ProfileStore:
    def __init__(self) -> None:
        self.custom_profiles = self._load_custom_profiles()

    @property
    def profiles(self) -> list[ScanProfile]:
        return [*BUILT_IN_PROFILES, *self.custom_profiles]

    def add_custom_profile(
        self,
        name: str,
        arguments: str,
        description: str,
    ) -> ScanProfile:
        profile = ScanProfile(
            name=name,
            arguments=arguments,
            description=description,
            is_built_in=False,
            id=uuid4(),
        )
        self.custom_profiles.append(profile)
        self._save()
        return profile

    def update_custom_profile(self, profile_id, name: str, arguments: str, description: str) -> None:
        for index, profile in enumerate(self.custom_profiles):
            if profile.id == profile_id:
                self.custom_profiles[index] = ScanProfile(
                    id=profile.id,
                    name=name,
                    arguments=arguments,
                    description=description,
                    is_built_in=False,
                )
                self._save()
                return

    def delete_custom_profile(self, profile_id) -> None:
        self.custom_profiles = [
            profile for profile in self.custom_profiles if profile.id != profile_id
        ]
        self._save()

    def duplicate_profile(self, profile: ScanProfile) -> ScanProfile:
        return self.add_custom_profile(
            name=f"{profile.name} Copy",
            arguments=profile.arguments,
            description=profile.description,
        )

    def merge_imported(self, imported_profiles: list[ScanProfile]) -> None:
        for imported in imported_profiles:
            existing = next(
                (profile for profile in self.custom_profiles if profile.name == imported.name),
                None,
            )
            if existing is not None:
                self.update_custom_profile(
                    existing.id,
                    imported.name,
                    imported.arguments,
                    imported.description,
                )
            else:
                self.custom_profiles.append(
                    ScanProfile(
                        id=imported.id,
                        name=imported.name,
                        arguments=imported.arguments,
                        description=imported.description,
                        is_built_in=False,
                    )
                )
        self._save()

    def export_custom_profiles(self, destination: str) -> int:
        Path(destination).write_text(encode_profiles(self.custom_profiles), encoding="utf-8")
        return len(self.custom_profiles)

    def import_custom_profiles(self, source: str) -> list[ScanProfile]:
        imported = [
            ScanProfile(
                id=profile.id,
                name=profile.name,
                arguments=profile.arguments,
                description=profile.description,
                is_built_in=False,
            )
            for profile in decode_profiles(Path(source).read_text(encoding="utf-8"))
            if profile.name.strip()
        ]
        self.merge_imported(imported)
        return imported

    def _load_custom_profiles(self) -> list[ScanProfile]:
        raw = read_json_file(custom_profiles_path(), "[]")
        try:
            return decode_profiles(raw)
        except (ValueError, TypeError):
            return []

    def _save(self) -> None:
        write_json_file(custom_profiles_path(), encode_profiles(self.custom_profiles))

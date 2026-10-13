"""Defines standard-agnostic data model for an SBOM."""

import abc
import urllib.parse
import uuid
from datetime import datetime
from enum import Enum, auto
import re
from typing import Dict, List, Optional, Set, Tuple


class ChecksumAlgorithm(Enum):
    SHA1 = auto()
    SHA224 = auto()
    SHA256 = auto()
    SHA384 = auto()
    SHA512 = auto()
    MD5 = auto()


class BasePackage(abc.ABC):
    """Represents a software package."""

    # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        name: str,
        version: str,
        filename: str = "",
        license_declared: str = "",
        vendor: str = "",
        checksums: Optional[Dict[ChecksumAlgorithm, str]] = None,
        homepage: str = "",
        download_url: str = "",
        build_date: Optional[datetime] = None,
        summary: str = "",
        description: str = "",
        depends_on: Optional[Set["BasePackage"]] = None,
        optional_depends_on: Optional[Set["BasePackage"]] = None,
    ) -> None:
        self.name = name
        self.version = version
        self.filename = filename
        self.license_declared = license_declared
        self.vendor = vendor
        self.checksums = checksums or {}
        self.homepage = homepage
        self.download_url = download_url
        self.build_date = build_date
        self.summary = summary
        self.description = description
        self.depends_on = depends_on or set()
        self.optional_depends_on = optional_depends_on or set()

    @abc.abstractmethod
    def uuid(self) -> str:
        """
        Returns a stable UUID for the package.
        """

    @abc.abstractmethod
    def source_info(self) -> str:
        """
        Return a string describing the source of the package.
        """

    @abc.abstractmethod
    def purl(self) -> str:
        """
        Return a Package URL for the package.

        The PURL format is:
        pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>

        Core PURL spec is defined at:
        https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst
        """


class RPMDependency:
    """Represents an RPM dependency or provided capability."""

    def __init__(self, name: str, relation: str = "", version: str = "") -> None:
        self.name = name
        self.relation = relation
        self.version = version

    def __str__(self) -> str:
        return f"{self.name} {self.relation} {self.version}"


# Map well-known RPM Vendor tags to the purl namespaces conventionally used for
# them (see purl-spec PURL-TYPES "rpm": e.g. pkg:rpm/fedora/..., pkg:rpm/redhat/...).
# Red Hat's security data (VEX/CSAF, TPA) matches on these namespaces.
RPM_VENDOR_PURL_NAMESPACES = {
    "fedora project": "fedora",
    "red hat, inc.": "redhat",
    "centos": "centos",
    "centos project": "centos",
    "almalinux": "almalinux",
    "rocky enterprise software foundation": "rocky",
    "opensuse": "opensuse",
    "suse llc <https://www.suse.com/>": "suse",
}


_HASH_LIKE_REPO_ID = re.compile(r"[0-9a-f]{32,}")


def rpm_repository_id(repo_id: str, repo_name: str = "") -> str:
    """Return the value for the purl repository_id qualifier.

    The DNF repository ID is used as is. Callers such as image-builder pass a
    content hash as repository ID; in that case the configured repository name
    (e.g. "BaseOS") is used instead, normalized to a purl-friendly token.
    """
    if repo_id and not _HASH_LIKE_REPO_ID.fullmatch(repo_id) and not repo_id.startswith("@"):
        return repo_id
    if repo_name:
        return re.sub(r"[^a-z0-9._]+", "-", repo_name.lower()).strip("-")
    return ""


def purl_rpm_namespace(vendor: str) -> str:
    """Return the purl namespace for an RPM Vendor tag.

    Known vendors are mapped to their conventional namespace. Unknown vendors
    fall back to the lower-cased vendor string (the previous behaviour).
    """
    return RPM_VENDOR_PURL_NAMESPACES.get(vendor.strip().lower(), vendor.lower())


class RPMPackage(BasePackage):
    """Represents an RPM package."""

    def __init__(
        self,
        name: str,
        version: str,
        release: str,
        architecture: str,
        epoch: int = 0,
        filename: str = "",
        license_declared: str = "",
        vendor: str = "",
        checksums: Optional[Dict[ChecksumAlgorithm, str]] = None,
        homepage: str = "",
        download_url: str = "",
        build_date: Optional[datetime] = None,
        summary: str = "",
        description: str = "",
        depends_on: Optional[Set["BasePackage"]] = None,
        optional_depends_on: Optional[Set["BasePackage"]] = None,
        repository_url: str = "",
        repository_id: str = "",
        source_rpm: str = "",
        rpm_provides: Optional[List[RPMDependency]] = None,
        rpm_requires: Optional[List[RPMDependency]] = None,
        rpm_recommends: Optional[List[RPMDependency]] = None,
        rpm_suggests: Optional[List[RPMDependency]] = None,
    ) -> None:
        super().__init__(
            name,
            version,
            filename,
            license_declared,
            vendor,
            checksums,
            homepage,
            download_url,
            build_date,
            summary,
            description,
            depends_on,
            optional_depends_on,
        )
        self.release = release
        self.architecture = architecture
        self.epoch = epoch
        self.repository_url = repository_url
        self.repository_id = repository_id
        self.source_rpm = source_rpm
        self.rpm_provides = rpm_provides or []
        self.rpm_requires = rpm_requires or []
        self.rpm_recommends = rpm_recommends or []
        self.rpm_suggests = rpm_suggests or []

    def source_info(self) -> str:
        """
        Return a string describing the source of the RPM package.
        """
        if self.source_rpm:
            return f"Source RPM: {self.source_rpm}"
        return ""

    def uuid(self) -> str:
        """
        Returns a stable UUID for the same RPM package as defined by the PURL.
        """
        return str(uuid.uuid3(uuid.NAMESPACE_URL, self._purl(with_repo_url=False)))

    def _purl(self, with_repo_url=True) -> str:
        """
        Return a Package URL for the RPM package.

        Optionally don't include the repository URL in the PURL. This is useful
        to generate a PURL that can be used to identify the same package, regardless
        of the repository it was found in.

        PURL spec for RPMs is defined at:
        https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#rpm
        """
        namespace = ""
        if self.vendor:
            namespace = f"{urllib.parse.quote(purl_rpm_namespace(self.vendor))}/"

        purl = f"pkg:rpm/{namespace}{self.name}@{self.version}-{self.release}?arch={self.architecture}"

        if self.epoch:
            purl += f"&epoch={self.epoch}"

        if with_repo_url and self.repository_id:
            # Red Hat SBOM guide, "RPM": repositories are identified by the
            # repository_id qualifier, e.g. repository_id=rhel-9-for-x86_64-baseos-rpms
            purl += f"&repository_id={urllib.parse.quote(self.repository_id, safe='')}"

        return purl

    def purl(self) -> str:
        return self._purl()

    def source_rpm_nvr(self) -> Optional[Tuple[str, str, str]]:
        """Split the source RPM file name (N-V-R.src.rpm) into (name, version, release)."""
        srpm = self.source_rpm
        if not srpm or not srpm.endswith(".src.rpm"):
            return None
        parts = srpm[:-len(".src.rpm")].rsplit("-", 2)
        if len(parts) != 3 or not all(parts):
            return None
        return parts[0], parts[1], parts[2]

    def source_rpm_purl(self) -> Optional[str]:
        """purl of the source RPM, as in the Red Hat SBOM guide: pkg:rpm/<ns>/<n>@<v>-<r>?arch=src[&epoch=E]."""
        nvr = self.source_rpm_nvr()
        if nvr is None:
            return None
        namespace = f"{urllib.parse.quote(purl_rpm_namespace(self.vendor))}/" if self.vendor else ""
        purl = f"pkg:rpm/{namespace}{nvr[0]}@{nvr[1]}-{nvr[2]}?arch=src"
        if self.epoch:
            purl += f"&epoch={self.epoch}"
        return purl

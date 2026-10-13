import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Union
from uuid import uuid4

import osbuild
import osbuild.util.sbom.model as sbom_model
import osbuild.util.sbom.spdx2 as spdx2

try:
    from license_expression import ExpressionError, get_spdx_licensing
except ImportError:
    get_spdx_licensing = None
    ExpressionError = None


# Human-readable texts for LicenseRefs commonly found in Fedora/RHEL RPM License
# tags (see https://docs.fedoraproject.org/en-US/legal/ and the fedora-license-data
# project). Unknown refs get a generic text; the ID is what matters for matching.
KNOWN_LICENSE_REF_TEXTS = {
    "LicenseRef-Fedora-Public-Domain":
        "Public domain dedication, as reviewed by Fedora Legal (fedora-license-data).",
    "LicenseRef-Callaway-Redistributable-no-modification-permitted":
        "Fedora legacy (Callaway) license: redistributable, no modification permitted (e.g. firmware).",
    "LicenseRef-Not-Copyrightable":
        "Material not subject to copyright, as reviewed by Fedora Legal (fedora-license-data).",
    "LicenseRef-scancode-public-domain":
        "Public domain (ScanCode license key 'public-domain').",
}


class SpdxLicenseExpressionCreator:
    """
    Class for creating SPDX license expressions from license strings.

    This class uses the license-expression package to parse license strings and convert them to SPDX license, if
    possible.

    The class object also keeps track of all extracted licensing information objects that were created during the
    conversion process. The extracted licensing information objects are stored in a dictionary, where the key is the
    license reference ID and the value is the ExtractedLicensingInfo object.
    """

    def __init__(self, license_index_location=None):
        self._extracted_license_infos: Dict[str, spdx2.ExtractedLicensingInfo] = {}
        self._spdx_licensing = None

        if get_spdx_licensing:
            if license_index_location:
                self._spdx_licensing = get_spdx_licensing(license_index_location)
            else:
                self._spdx_licensing = get_spdx_licensing()
        elif license_index_location:
            raise ValueError("The license-expression package is not available. "
                             "Specify the license index location has no effect.")

    _LICENSE_REF_RE = re.compile(r"LicenseRef-[A-Za-z0-9.\-]+")
    _LICENSE_REF_PLUS_RE = re.compile(r"LicenseRef-[A-Za-z0-9.\-]+\+?")

    def _register_license_refs(self, expression: str) -> None:
        """
        Make sure every LicenseRef-* used inside a license expression is defined.

        SPDX 2.3 (clause 10) requires every LicenseRef used in the document to be
        declared in hasExtractedLicensingInfos. Fedora license tags legitimately use
        LicenseRefs (e.g. LicenseRef-Fedora-Public-Domain, LicenseRef-Callaway-*),
        and license-expression maps some keys to LicenseRef-scancode-*. Without a
        definition, strict validators (spdx-tools, mobster) reject the document.
        """
        for ref in self._LICENSE_REF_RE.findall(expression):
            if ref in self._extracted_license_infos:
                continue
            self._extracted_license_infos[ref] = spdx2.ExtractedLicensingInfo(
                extracted_text=KNOWN_LICENSE_REF_TEXTS.get(
                    ref, f"License identifier {ref} as declared in the RPM License tag."),
                name=ref[len("LicenseRef-"):],
                license_ref_id=ref,
            )

    def _to_extracted_license_info(self, license_str: str) -> spdx2.ExtractedLicensingInfo:
        eli = spdx2.ExtractedLicensingInfo(license_str)
        return self._extracted_license_infos.setdefault(eli.license_ref_id, eli)

    def ensure_license_expression(self, license_str: str) -> Union[str, spdx2.ExtractedLicensingInfo]:
        """
        Convert a license string to a valid SPDX license expression or wrap it in an ExtractedLicensingInfo object.

        This function uses the license-expression package to parse the license string and convert it to an SPDX license
        expression. If the license string can't be parsed and converted to an SPDX license expression, it is wrapped in an
        ExtractedLicensingInfo object.

        If the license-expression package is not available, the license string is always wrapped in an
        ExtractedLicensingInfo object.

        License strings that are already SPDX license ref IDs are returned as is.
        """
        if license_str.startswith("LicenseRef-") and self._LICENSE_REF_RE.fullmatch(license_str):
            # The license string is already an SPDX license ref ID.
            self._register_license_refs(license_str)
            return license_str

        if self._spdx_licensing is None:
            return self._to_extracted_license_info(license_str)

        # Fedora/RHEL License tags are SPDX expressions that may use LicenseRef-*
        # identifiers (e.g. LicenseRef-Callaway-BSD). Keep those verbatim: hide them
        # behind placeholders so that license-expression neither rejects them as
        # unknown keys nor rewrites them to aliases (it maps
        # LicenseRef-Fedora-Public-Domain to LicenseRef-scancode-public-domain).
        refs: Dict[str, str] = {}

        def _hide(match):
            placeholder = f"LicenseRef-osbuild-placeholder-{len(refs)}"
            ref = match.group(0)
            if ref.endswith("+"):
                # e.g. Fedora's legacy "LicenseRef-Callaway-LGPLv2+": '+' is not
                # allowed in a LicenseRef idstring (SPDX 2.3 Annex D), so spell the
                # "or later" into the identifier.
                ref = ref[:-1] + "-or-later"
            refs[placeholder] = ref
            return placeholder

        hidden = self._LICENSE_REF_PLUS_RE.sub(_hide, license_str)
        try:
            parsed = self._spdx_licensing.parse(hidden)
            unknown = [k for k in self._spdx_licensing.unknown_license_keys(parsed) if k not in refs]
            if parsed is None or unknown:
                raise ExpressionError(f"Unknown license key(s): {unknown}")
            # validate the remaining (non-LicenseRef) keys strictly
            self._spdx_licensing.validate(hidden, strict=True)
        except ExpressionError:
            return self._to_extracted_license_info(license_str)
        expression = str(parsed)
        for placeholder in sorted(refs, key=len, reverse=True):
            expression = expression.replace(placeholder, refs[placeholder])
        self._register_license_refs(expression)
        return expression

    def extracted_license_infos(self) -> List[spdx2.ExtractedLicensingInfo]:
        """
        Return a list of all extracted licensing information objects that were created during the conversion process.
        """
        return list(self._extracted_license_infos.values())


def spdx2_checksum_algorithm(algorithm: sbom_model.ChecksumAlgorithm) -> spdx2.ChecksumAlgorithm:
    if algorithm == sbom_model.ChecksumAlgorithm.SHA1:
        return spdx2.ChecksumAlgorithm.SHA1
    if algorithm == sbom_model.ChecksumAlgorithm.SHA224:
        return spdx2.ChecksumAlgorithm.SHA224
    if algorithm == sbom_model.ChecksumAlgorithm.SHA256:
        return spdx2.ChecksumAlgorithm.SHA256
    if algorithm == sbom_model.ChecksumAlgorithm.SHA384:
        return spdx2.ChecksumAlgorithm.SHA384
    if algorithm == sbom_model.ChecksumAlgorithm.SHA512:
        return spdx2.ChecksumAlgorithm.SHA512
    if algorithm == sbom_model.ChecksumAlgorithm.MD5:
        return spdx2.ChecksumAlgorithm.MD5
    raise ValueError(f"Unknown checksum algorithm: {algorithm}")


def create_spdx2_document():
    tool = f"osbuild-{osbuild.__version__}"
    doc_name = f"sbom-by-{tool}"

    ci = spdx2.CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id="SPDXRef-DOCUMENT",
        name=doc_name,
        data_license="CC0-1.0",
        document_namespace=f"https://osbuild.org/spdxdocs/{doc_name}-{uuid4()}",
        creators=[spdx2.Creator(spdx2.CreatorType.TOOL, tool)],
        created=datetime.now(),
    )
    doc = spdx2.Document(ci)

    return doc


def _package_version_info(pkg: sbom_model.BasePackage) -> str:
    """versionInfo for a package; for RPMs this is VERSION-RELEASE (as in the purl)."""
    release = getattr(pkg, "release", None)
    if release:
        return f"{pkg.version}-{release}"
    return pkg.version


def sbom_pkgset_to_spdx2_doc(
        pkgset: List[sbom_model.BasePackage],
        license_index_location: Optional[os.PathLike] = None) -> spdx2.Document:
    doc = create_spdx2_document()
    relationships = []
    license_expr_creator = SpdxLicenseExpressionCreator(license_index_location)

    for pkg in pkgset:

        download_location: Union[str, spdx2.NoAssertionValue] = spdx2.NoAssertionValue()
        if pkg.download_url:
            download_location = pkg.download_url

        license_declared = license_expr_creator.ensure_license_expression(pkg.license_declared)

        p = spdx2.Package(
            spdx_id=f"SPDXRef-{pkg.uuid()}",
            name=pkg.name,
            download_location=download_location,
            version=_package_version_info(pkg),
            files_analyzed=False,
            license_declared=license_declared,
            external_references=[
                spdx2.ExternalPackageRef(
                    category=spdx2.ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type="purl",
                    locator=pkg.purl(),
                )
            ]
        )

        if pkg.homepage:
            p.homepage = pkg.homepage

        # SPDX 2.3 7.5 supplier / 7.4 packageFileName; required by the Red Hat
        # ProdSec SBOM guide (checked by sbomgrader)
        p.supplier = f"Organization: {pkg.vendor}" if pkg.vendor else spdx2.NoAssertionValue()
        if pkg.filename:
            p.file_name = pkg.filename

        if pkg.summary:
            p.summary = pkg.summary

        if pkg.description:
            p.description = pkg.description

        if pkg.source_info():
            p.source_info = pkg.source_info()

        for hash_type, hash_value in pkg.checksums.items():
            p.checksums.append(
                spdx2.Checksum(
                    algorithm=spdx2_checksum_algorithm(hash_type),
                    value=hash_value,
                )
            )

        if pkg.build_date:
            p.built_date = pkg.build_date

        doc.packages.append(p)

        relationships.append(
            spdx2.Relationship(
                spdx_element_id=doc.creation_info.spdx_id,
                relationship_type=spdx2.RelationshipType.DESCRIBES,
                related_spdx_element_id=p.spdx_id,
            )
        )

        for dep in sorted(pkg.depends_on, key=lambda x: x.uuid()):
            relationships.append(
                spdx2.Relationship(
                    spdx_element_id=p.spdx_id,
                    relationship_type=spdx2.RelationshipType.DEPENDS_ON,
                    related_spdx_element_id=f"SPDXRef-{dep.uuid()}",
                )
            )

        for optional_dep in sorted(pkg.optional_depends_on, key=lambda x: x.uuid()):
            relationships.append(
                spdx2.Relationship(
                    spdx_element_id=f"SPDXRef-{optional_dep.uuid()}",
                    relationship_type=spdx2.RelationshipType.OPTIONAL_DEPENDENCY_OF,
                    related_spdx_element_id=p.spdx_id,
                )
            )

    doc.relationships = relationships

    extracted_license_infos = license_expr_creator.extracted_license_infos()
    if len(extracted_license_infos) > 0:
        doc.extracted_licensing_infos = extracted_license_infos

    return doc

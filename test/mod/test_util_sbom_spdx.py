import pytest

import osbuild
from osbuild.util.sbom.spdx import (
    SpdxLicenseExpressionCreator,
    create_spdx2_document,
    sbom_pkgset_to_spdx2_doc,
    spdx2_checksum_algorithm,
)
from osbuild.util.sbom.spdx2.model import (
    CreatorType,
    ExternalPackageRefCategory,
    ExtractedLicensingInfo,
    RelationshipType,
)

from ..test import patch_license_expression

CUSTOM_LICENSE_DB_LOCATION = "./test/data/spdx/custom-license-index.json"


@pytest.mark.parametrize("licensing_available", (True, False))
def test_spdxlicenseexpressionfactory_license_expression_availability(licensing_available):
    with patch_license_expression(licensing_available) as mocked_licensing:
        lf = SpdxLicenseExpressionCreator()
        license_expression = lf.ensure_license_expression("MIT")

        license_expression2 = lf.ensure_license_expression("LicenseRef-123")
        assert license_expression2 == "LicenseRef-123"

        if licensing_available:
            assert mocked_licensing is not None
            # The license string should be a SPDX license expression string.
            assert license_expression == "MIT"
            # LicenseRef-123 must be defined in hasExtractedLicensingInfos (SPDX 2.3 clause 10)
            assert [eli.license_ref_id for eli in lf.extracted_license_infos()] == ["LicenseRef-123"]
        else:
            assert mocked_licensing is None
            # The license string should be wrapped in an ExtractedLicensingInfo,
            # because the license-expression package is not available.
            assert isinstance(license_expression, ExtractedLicensingInfo)
            assert str(license_expression).startswith("LicenseRef-")
            assert license_expression.extracted_text == "MIT"
            # the wrapped "MIT" plus the definition of LicenseRef-123
            assert len(lf.extracted_license_infos()) == 2


@pytest.mark.parametrize("licensing_available", (True, False))
def test_spdxlicenseexpressionfactory_custom_license_index(licensing_available):
    with patch_license_expression(licensing_available) as mocked_licensing:
        if licensing_available:
            assert mocked_licensing is not None
            lf = SpdxLicenseExpressionCreator(CUSTOM_LICENSE_DB_LOCATION)
            license_text = "GPLv2"
            license_expression = lf.ensure_license_expression(license_text)
            assert license_expression == license_text
            assert len(lf.extracted_license_infos()) == 0
        else:
            assert mocked_licensing is None
            with pytest.raises(ValueError, match="The license-expression package is not available. " +
                               "Specify the license index location has no effect."):
                lf = SpdxLicenseExpressionCreator(CUSTOM_LICENSE_DB_LOCATION)


def test_create_spdx2_document():
    doc1 = create_spdx2_document()

    assert doc1.creation_info.spdx_version == "SPDX-2.3"
    assert doc1.creation_info.spdx_id == "SPDXRef-DOCUMENT"
    assert doc1.creation_info.name == f"sbom-by-osbuild-{osbuild.__version__}"
    assert doc1.creation_info.data_license == "CC0-1.0"
    assert doc1.creation_info.document_namespace.startswith("https://osbuild.org/spdxdocs/sbom-by-osbuild-")
    assert len(doc1.creation_info.creators) == 1
    assert doc1.creation_info.creators[0].creator_type == CreatorType.TOOL
    assert doc1.creation_info.creators[0].name == f"osbuild-{osbuild.__version__}"
    assert doc1.creation_info.created

    doc2 = create_spdx2_document()
    assert doc1.creation_info.document_namespace != doc2.creation_info.document_namespace
    assert doc1.creation_info.created != doc2.creation_info.created

    doc1_dict = doc1.to_dict()
    doc2_dict = doc2.to_dict()
    del doc1_dict["creationInfo"]["created"]
    del doc2_dict["creationInfo"]["created"]
    del doc1_dict["documentNamespace"]
    del doc2_dict["documentNamespace"]
    assert doc1_dict == doc2_dict


@pytest.mark.parametrize("licensing_available", (True, False))
@pytest.mark.parametrize("license_index_location", (None, CUSTOM_LICENSE_DB_LOCATION))
def test_sbom_pkgset_to_spdx2_doc(repo_servers, licensing_available, license_index_location):
    testutil_dnf4 = pytest.importorskip("osbuild.testutil.dnf4")
    bom_dnf = pytest.importorskip("osbuild.util.sbom.dnf")

    dnf_pkgset = testutil_dnf4.depsolve_pkgset(repo_servers, ["bash"])
    bom_pkgset = bom_dnf.dnf_pkgset_to_sbom_pkgset(dnf_pkgset)

    with patch_license_expression(licensing_available) as _:
        extracted_licensing_infos = set()

        try:
            doc = sbom_pkgset_to_spdx2_doc(bom_pkgset, license_index_location)
        except ValueError:
            # ValueError can be raised only if the license-expression package is not available
            # and a custom license index file is used.
            if not licensing_available and license_index_location:
                return
        else:
            if not licensing_available and license_index_location:
                pytest.fail("Expected a ValueError to be raised when the license-expression package is not available.")

        assert len(doc.packages) == len(bom_pkgset)
        for spdx_pkg, bom_pkg in zip(doc.packages, bom_pkgset):
            assert spdx_pkg.spdx_id == f"SPDXRef-{bom_pkg.uuid()}"
            assert spdx_pkg.name == bom_pkg.name
            assert spdx_pkg.version == f"{bom_pkg.version}-{bom_pkg.release}"
            assert not spdx_pkg.files_analyzed
            assert spdx_pkg.download_location == bom_pkg.download_url
            assert spdx_pkg.homepage == bom_pkg.homepage
            assert spdx_pkg.summary == bom_pkg.summary
            assert spdx_pkg.description == bom_pkg.description
            assert spdx_pkg.source_info == bom_pkg.source_info()
            assert spdx_pkg.built_date == bom_pkg.build_date

            # If the license-expression package is available and no custom license index file is used, only the "MIT"
            # license is converted as a valid SPDX license expression for our testing package set. Otherwise, also the
            # "GPLv2" license is converted as a valid SPDX license expression.
            valid_licenses = ["MIT"]
            if license_index_location:
                valid_licenses.append("GPLv2")

            if licensing_available and bom_pkg.license_declared in valid_licenses:
                assert isinstance(spdx_pkg.license_declared, str)
                assert spdx_pkg.license_declared in valid_licenses
            # If the license-expression package is not available, all licenses are converted
            # to SPDX license references.
            # The same applies to all licenses that are not "MIT" if the package is available,
            # because the testing package set contains only "MIT" as a valid SPDX license expression.
            else:
                assert isinstance(spdx_pkg.license_declared, ExtractedLicensingInfo)
                assert str(spdx_pkg.license_declared).startswith("LicenseRef-")
                assert spdx_pkg.license_declared.extracted_text == bom_pkg.license_declared
                extracted_licensing_infos.add(spdx_pkg.license_declared)

            assert len(spdx_pkg.checksums) == 1
            assert spdx_pkg.checksums[0].algorithm == spdx2_checksum_algorithm(list(bom_pkg.checksums.keys())[0])
            assert spdx_pkg.checksums[0].value == list(bom_pkg.checksums.values())[0]

            assert len(spdx_pkg.external_references) == 1
            assert spdx_pkg.external_references[0].category == ExternalPackageRefCategory.PACKAGE_MANAGER
            assert spdx_pkg.external_references[0].reference_type == "purl"
            assert spdx_pkg.external_references[0].locator == bom_pkg.purl()

        assert len([rel for rel in doc.relationships if rel.relationship_type ==
                    RelationshipType.DESCRIBES]) == len(bom_pkgset)

        deps_count = sum(len(bom_pkg.depends_on) for bom_pkg in bom_pkgset)
        assert len([rel for rel in doc.relationships if rel.relationship_type ==
                    RelationshipType.DEPENDS_ON]) == deps_count

        optional_deps_count = sum(len(bom_pkg.optional_depends_on) for bom_pkg in bom_pkgset)
        assert len([rel for rel in doc.relationships if rel.relationship_type ==
                    RelationshipType.OPTIONAL_DEPENDENCY_OF]) == optional_deps_count

        assert len(extracted_licensing_infos) > 0
        assert sorted(extracted_licensing_infos, key=lambda x: x.license_ref_id) == \
            sorted(doc.extracted_licensing_infos, key=lambda x: x.license_ref_id)


def test_sbom_pkgset_to_spdx2_doc_rpm_fields():
    # pylint: disable=import-outside-toplevel
    from osbuild.util.sbom.model import ChecksumAlgorithm, RPMPackage

    glibc = RPMPackage("glibc", "2.40", "1.fc41", "x86_64", vendor="Fedora Project",
                       checksums={ChecksumAlgorithm.SHA256: "a" * 64}, filename="glibc-2.40-1.fc41.x86_64.rpm")
    doc = sbom_pkgset_to_spdx2_doc([glibc, RPMPackage("a", "1", "1", "noarch")]).to_dict()
    names = {p["name"]: p for p in doc["packages"]}
    assert names["glibc"]["versionInfo"] == "2.40-1.fc41"
    assert names["glibc"]["supplier"] == "Organization: Fedora Project"
    assert names["glibc"]["packageFileName"] == "glibc-2.40-1.fc41.x86_64.rpm"
    assert names["glibc"]["externalRefs"][0]["referenceLocator"].startswith("pkg:rpm/fedora/glibc@2.40-1.fc41")
    assert names["a"]["supplier"] == "NOASSERTION"
    assert [r["relationshipType"] for r in doc["relationships"]] == ["DESCRIBES", "DESCRIBES"]


def test_all_license_refs_are_defined():
    pytest.importorskip("license_expression")
    # pylint: disable=import-outside-toplevel
    import re

    from osbuild.util.sbom.model import RPMPackage

    pkgs = [
        RPMPackage("fw", "1", "1", "noarch", license_declared="LicenseRef-Callaway-Redistributable-no-modification-permitted"),
        RPMPackage("tz", "1", "1", "noarch", license_declared="LicenseRef-Fedora-Public-Domain AND MIT"),
        RPMPackage("pd", "1", "1", "noarch", license_declared="LicenseRef-Fedora-Public-Domain"),
        RPMPackage("old", "1", "1", "noarch", license_declared="GPLv2+ and weird stuff"),
    ]
    doc = sbom_pkgset_to_spdx2_doc(pkgs).to_dict()
    used = set()
    for p in doc["packages"]:
        used.update(re.findall(r"LicenseRef-[A-Za-z0-9.\-]+", p["licenseDeclared"]))
    defined = {eli["licenseId"] for eli in doc["hasExtractedLicensingInfos"]}
    assert used and used <= defined
    assert len(defined) == len(doc["hasExtractedLicensingInfos"])  # no duplicates


def test_fedora_license_refs_kept_verbatim():
    pytest.importorskip("license_expression")
    lf = SpdxLicenseExpressionCreator()
    # license-expression would alias this to LicenseRef-scancode-public-domain
    pd = "LicenseRef-Fedora-Public-Domain"
    assert lf.ensure_license_expression(pd) == pd
    # unknown-to-scancode Fedora refs inside valid SPDX expressions stay expressions
    assert lf.ensure_license_expression("mit and LicenseRef-Callaway-BSD") == "MIT AND LicenseRef-Callaway-BSD"
    # '+' is not valid in a LicenseRef idstring
    assert lf.ensure_license_expression("LicenseRef-Callaway-LGPLv2+") == "LicenseRef-Callaway-LGPLv2-or-later"
    assert {eli.license_ref_id for eli in lf.extracted_license_infos()} == {
        "LicenseRef-Fedora-Public-Domain", "LicenseRef-Callaway-BSD", "LicenseRef-Callaway-LGPLv2-or-later"}
